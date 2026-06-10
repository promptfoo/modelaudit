"""Shared security helpers for archive member names and source analysis."""

from __future__ import annotations

import ast
import math
import re
import shlex
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from types import EllipsisType
from typing import TYPE_CHECKING, Literal

from ._archive_outcomes import mark_archive_scan_incomplete
from .base import IssueSeverity

if TYPE_CHECKING:
    from .base import ScanResult

_EXECUTABLE_ARCHIVE_MEMBER_MAGIC_READ_BYTES = 1024
_PORTABLE_EXECUTABLE_POINTER_OFFSET = 0x3C
_PORTABLE_EXECUTABLE_MIN_HEADER_OFFSET = 0x40
_PORTABLE_EXECUTABLE_MAX_HEADER_OFFSET = 1024 * 1024
_PORTABLE_EXECUTABLE_SIGNATURE = b"PE\x00\x00"
ExecutableArchiveMemberProbeOutcome = Literal["detected", "absent", "incomplete"]
_EXECUTABLE_ARCHIVE_MEMBER_MAGIC_PREFIXES = (
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"#!",
)
_MACHO_FAT_MAGIC_32_BE = b"\xca\xfe\xba\xbe"
_MACHO_FAT_MAGIC_32_LE = b"\xbe\xba\xfe\xca"
_MACHO_FAT_MAGIC_64_BE = b"\xca\xfe\xba\xbf"
_MACHO_FAT_MAGIC_64_LE = b"\xbf\xba\xfe\xca"
_MACHO_FAT_MAGICS = {
    _MACHO_FAT_MAGIC_32_BE,
    _MACHO_FAT_MAGIC_32_LE,
    _MACHO_FAT_MAGIC_64_BE,
    _MACHO_FAT_MAGIC_64_LE,
}
_VERSIONED_SHARED_OBJECT_SUFFIX_RE = re.compile(r"\.so(?:\.[0-9]+)+$")
_PYTHON_ARCHIVE_MEMBER_SUFFIXES = (".py", ".pyw")
_PYTHON_SHEBANG_COMMAND_RE = re.compile(r"^(?:python(?:\d+(?:\.\d+)*)?w?|pypy(?:\d+(?:\.\d+)*)?)$")
_ENV_SHEBANG_OPTIONS_WITH_ARGUMENT = frozenset({"-u", "--unset", "-C", "--chdir"})
_OS_PROCESS_EXECUTION_CALLS = frozenset(
    {
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.popen",
        "os.posix_spawn",
        "os.posix_spawnp",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.startfile",
        "os.system",
    }
)
_ASYNCIO_PROCESS_EXECUTION_CALLS = frozenset(
    {
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "asyncio.subprocess.create_subprocess_exec",
        "asyncio.subprocess.create_subprocess_shell",
    }
)
_SUBPROCESS_PROCESS_EXECUTION_CALLS = frozenset(
    {
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.run",
    }
)
_RUNPY_CODE_EXECUTION_CALLS = frozenset(
    {
        "runpy._run_module_as_main",
        "runpy.run_module",
        "runpy.run_path",
    }
)
_WEBBROWSER_LAUNCH_CALLS = frozenset(
    {
        "webbrowser.open",
        "webbrowser.open_new",
        "webbrowser.open_new_tab",
    }
)
_WEBBROWSER_CONTROLLER_FACTORIES = frozenset({"webbrowser.get"})
_WEBBROWSER_CONTROLLER_LAUNCH_METHODS = frozenset({"open", "open_new", "open_new_tab"})
_CTYPES_LIBRARY_LOADER_INSTANCE_ROOT = "ctypes.LibraryLoader.__instance__"
_CTYPES_DYNAMIC_LIBRARY_NAME = "<dynamic>"
_CTYPES_LIBRARY_LOADER_OBJECTS = frozenset(
    {
        _CTYPES_LIBRARY_LOADER_INSTANCE_ROOT,
        "ctypes.cdll",
        "ctypes.oledll",
        "ctypes.pydll",
        "ctypes.windll",
    }
)
_CTYPES_LIBRARY_LOADER_DISPLAY_ROOTS = {_CTYPES_LIBRARY_LOADER_INSTANCE_ROOT: "ctypes.LibraryLoader"}
_CTYPES_LIBRARY_LOADER_NON_LOADING_ATTRIBUTES = frozenset({"_FuncPtr", "_dlltype", "_handle", "_name"})
_CTYPES_LIBRARY_LOADER_CONSTRUCTORS = frozenset({"ctypes.LibraryLoader"})
_CTYPES_LIBRARY_LOADER_TYPES = frozenset(
    {
        "ctypes.CDLL",
        "ctypes.OleDLL",
        "ctypes.PyDLL",
        "ctypes.WinDLL",
    }
)
_CTYPES_LIBRARY_LOADER_TYPE_ALIASES = frozenset(
    f"{loader_root}._dlltype"
    for loader_root in _CTYPES_LIBRARY_LOADER_OBJECTS
    if loader_root != _CTYPES_LIBRARY_LOADER_INSTANCE_ROOT
)
_CTYPES_LOADER_INIT_KEYWORDS = frozenset({"self", "name", "mode", "handle", "use_errno", "use_last_error", "winmode"})
_CTYPES_LOADER_INIT_ARGUMENTS = ("self", "name", "mode", "handle", "use_errno", "use_last_error", "winmode")
_CTYPES_NATIVE_LIBRARY_LOADING_CALLS = frozenset(
    {
        "ctypes.CDLL",
        "ctypes.OleDLL",
        "ctypes.PyDLL",
        "ctypes.WinDLL",
        "ctypes.cdll.__getitem__",
        "ctypes.cdll.LoadLibrary",
        "ctypes.oledll.__getitem__",
        "ctypes.oledll.LoadLibrary",
        "ctypes.pydll.__getitem__",
        "ctypes.pydll.LoadLibrary",
        "ctypes.windll.__getitem__",
        "ctypes.windll.LoadLibrary",
    }
)
_STATIC_OVERWRITABLE_HIGH_RISK_REFERENCES = (
    _RUNPY_CODE_EXECUTION_CALLS
    | _WEBBROWSER_LAUNCH_CALLS
    | _WEBBROWSER_CONTROLLER_FACTORIES
    | _CTYPES_NATIVE_LIBRARY_LOADING_CALLS
    | _CTYPES_LIBRARY_LOADER_OBJECTS
    | _CTYPES_LIBRARY_LOADER_CONSTRUCTORS
)
_STATIC_TRUTHY_BUILTIN_REFERENCES = frozenset({"builtins.print", "builtins.len"})
_STATIC_EAGER_GENERATOR_CONSUMER_REFERENCES = frozenset(
    name
    for consumer in {"list", "max", "min", "set", "sorted", "sum", "tuple"}
    for name in (
        consumer,
        f"builtins.{consumer}",
    )
)
_STATIC_SIDE_EFFECT_FREE_BUILTIN_REFERENCES = frozenset({"builtins.object", "builtins.type"})
_STATIC_DISPATCH_DECORATOR_REFERENCES = frozenset({"builtins.staticmethod", "builtins.classmethod"})
_STATIC_CLASS_CREATION_REFERENCES = frozenset({"builtins.__build_class__"})
_STATIC_MODULE_REGISTRY_REFERENCES = frozenset({"sys.modules"})
_STATIC_MODULE_TYPE_REFERENCES = frozenset(
    f"{root}.__class__" for root in {"builtins", "contextlib", "ctypes", "runpy", "sys", "webbrowser"}
)
_STATIC_MUTABLE_BUILTIN_HELPER_REFERENCES = frozenset(
    {"builtins.getattr", "builtins.vars", "builtins.setattr", "builtins.delattr"}
)
_STATIC_CONTEXT_MANAGER_HELPER_REFERENCES = frozenset({"contextlib.nullcontext"})
_STATIC_OPERATOR_ACCESSOR_HELPER_REFERENCES = frozenset(
    {"operator.attrgetter", "operator.itemgetter", "operator.methodcaller"}
)
_STATIC_KNOWN_PRESENT_MODULE_REFERENCES = frozenset({"os.getcwd"})
_STATIC_CTYPES_LIBRARY_LOADER_CONSTRUCTION_DISPATCH_REFERENCES = frozenset(
    {"ctypes.LibraryLoader.__new__", "ctypes.LibraryLoader.__init__", "ctypes.LibraryLoader.__setattr__"}
)
_STATIC_CTYPES_LIBRARY_LOADER_ATTRIBUTE_DISPATCH_REFERENCES = frozenset(
    {"ctypes.LibraryLoader.__getattribute__", "ctypes.LibraryLoader.__getattr__", "ctypes.LibraryLoader.__setattr__"}
)
_STATIC_CTYPES_LIBRARY_LOADER_EXISTING_ATTRIBUTE_DISPATCH_REFERENCES = frozenset(
    {"ctypes.LibraryLoader.__getattribute__"}
)
_STATIC_CTYPES_LIBRARY_LOADER_ITEM_DISPATCH_REFERENCES = frozenset(
    {
        "ctypes.LibraryLoader.__getitem__",
        "ctypes.LibraryLoader.__getattribute__",
        "ctypes.LibraryLoader.__getattr__",
        "ctypes.LibraryLoader.__setattr__",
    }
)
_STATIC_CTYPES_LIBRARY_LOADER_LOAD_LIBRARY_DISPATCH_REFERENCES = frozenset(
    {"ctypes.LibraryLoader.__getattribute__", "ctypes.LibraryLoader.LoadLibrary"}
)
_STATIC_CTYPES_LIBRARY_LOADER_MUTATION_DISPATCH_REFERENCES = frozenset({"ctypes.LibraryLoader.__setattr__"})
_STATIC_CTYPES_LIBRARY_LOADER_DELETE_DISPATCH_REFERENCES = frozenset({"ctypes.LibraryLoader.__delattr__"})
_STATIC_CTYPES_LIBRARY_LOADER_ITEM_STORE_DISPATCH_REFERENCES = frozenset({"ctypes.LibraryLoader.__setitem__"})
_STATIC_CTYPES_LIBRARY_LOADER_ITEM_DELETE_DISPATCH_REFERENCES = frozenset({"ctypes.LibraryLoader.__delitem__"})
_STATIC_CTYPES_LIBRARY_LOADER_TRUTH_DISPATCH_REFERENCES = frozenset(
    {"ctypes.LibraryLoader.__bool__", "ctypes.LibraryLoader.__len__"}
)
_STATIC_CTYPES_LIBRARY_LOADER_CALL_DISPATCH_REFERENCES = frozenset({"ctypes.LibraryLoader.__call__"})
_STATIC_CTYPES_LIBRARY_LOADER_GENERIC_PROTOCOL_DISPATCH_REFERENCES = frozenset(
    {
        "ctypes.LibraryLoader.__bool__",
        "ctypes.LibraryLoader.__len__",
        "ctypes.LibraryLoader.__iter__",
        "ctypes.LibraryLoader.__aiter__",
        "ctypes.LibraryLoader.__anext__",
        "ctypes.LibraryLoader.__reversed__",
        "ctypes.LibraryLoader.__contains__",
        "ctypes.LibraryLoader.__eq__",
        "ctypes.LibraryLoader.__ne__",
        "ctypes.LibraryLoader.__lt__",
        "ctypes.LibraryLoader.__le__",
        "ctypes.LibraryLoader.__gt__",
        "ctypes.LibraryLoader.__ge__",
        "ctypes.LibraryLoader.__format__",
        "ctypes.LibraryLoader.__str__",
        "ctypes.LibraryLoader.__repr__",
        "ctypes.LibraryLoader.__hash__",
        "ctypes.LibraryLoader.__index__",
        "ctypes.LibraryLoader.__enter__",
        "ctypes.LibraryLoader.__exit__",
        "ctypes.LibraryLoader.__aenter__",
        "ctypes.LibraryLoader.__aexit__",
        "ctypes.LibraryLoader.__await__",
        "ctypes.LibraryLoader.__mro_entries__",
        "ctypes.LibraryLoader.__call__",
        "ctypes.LibraryLoader.keys",
        "ctypes.LibraryLoader.__getitem__",
        "ctypes.LibraryLoader.__setitem__",
        "ctypes.LibraryLoader.__delitem__",
        "ctypes.LibraryLoader.__pos__",
        "ctypes.LibraryLoader.__neg__",
        "ctypes.LibraryLoader.__invert__",
        "ctypes.LibraryLoader.__add__",
        "ctypes.LibraryLoader.__radd__",
        "ctypes.LibraryLoader.__iadd__",
        "ctypes.LibraryLoader.__sub__",
        "ctypes.LibraryLoader.__rsub__",
        "ctypes.LibraryLoader.__isub__",
        "ctypes.LibraryLoader.__mul__",
        "ctypes.LibraryLoader.__rmul__",
        "ctypes.LibraryLoader.__imul__",
        "ctypes.LibraryLoader.__matmul__",
        "ctypes.LibraryLoader.__rmatmul__",
        "ctypes.LibraryLoader.__imatmul__",
        "ctypes.LibraryLoader.__truediv__",
        "ctypes.LibraryLoader.__rtruediv__",
        "ctypes.LibraryLoader.__itruediv__",
        "ctypes.LibraryLoader.__floordiv__",
        "ctypes.LibraryLoader.__rfloordiv__",
        "ctypes.LibraryLoader.__ifloordiv__",
        "ctypes.LibraryLoader.__mod__",
        "ctypes.LibraryLoader.__rmod__",
        "ctypes.LibraryLoader.__imod__",
        "ctypes.LibraryLoader.__divmod__",
        "ctypes.LibraryLoader.__rdivmod__",
        "ctypes.LibraryLoader.__pow__",
        "ctypes.LibraryLoader.__rpow__",
        "ctypes.LibraryLoader.__ipow__",
        "ctypes.LibraryLoader.__lshift__",
        "ctypes.LibraryLoader.__rlshift__",
        "ctypes.LibraryLoader.__ilshift__",
        "ctypes.LibraryLoader.__rshift__",
        "ctypes.LibraryLoader.__rrshift__",
        "ctypes.LibraryLoader.__irshift__",
        "ctypes.LibraryLoader.__and__",
        "ctypes.LibraryLoader.__rand__",
        "ctypes.LibraryLoader.__iand__",
        "ctypes.LibraryLoader.__xor__",
        "ctypes.LibraryLoader.__rxor__",
        "ctypes.LibraryLoader.__ixor__",
        "ctypes.LibraryLoader.__or__",
        "ctypes.LibraryLoader.__ror__",
        "ctypes.LibraryLoader.__ior__",
    }
)
_STATIC_CTYPES_LIBRARY_LOADER_ITERATION_DISPATCH_REFERENCES = frozenset(
    {"ctypes.LibraryLoader.__iter__", "ctypes.LibraryLoader.__getitem__"}
)
_STATIC_CTYPES_LIBRARY_LOADER_ASYNC_ITERATION_DISPATCH_REFERENCES = frozenset(
    {"ctypes.LibraryLoader.__aiter__", "ctypes.LibraryLoader.__anext__"}
)
_STATIC_CTYPES_LIBRARY_LOADER_HASH_DISPATCH_REFERENCES = frozenset({"ctypes.LibraryLoader.__hash__"})
_STATIC_CTYPES_LIBRARY_LOADER_MAPPING_EXPANSION_DISPATCH_REFERENCES = frozenset(
    {"ctypes.LibraryLoader.keys", "ctypes.LibraryLoader.__getitem__"}
)
_STATIC_CTYPES_LIBRARY_LOADER_FORMAT_DISPATCH_REFERENCES = frozenset(
    {"ctypes.LibraryLoader.__format__", "ctypes.LibraryLoader.__str__", "ctypes.LibraryLoader.__repr__"}
)
_STATIC_CTYPES_LIBRARY_LOADER_INDEX_DISPATCH_REFERENCES = frozenset({"ctypes.LibraryLoader.__index__"})
_STATIC_CTYPES_LIBRARY_LOADER_CONTEXT_DISPATCH_REFERENCES = frozenset(
    {"ctypes.LibraryLoader.__enter__", "ctypes.LibraryLoader.__exit__"}
)
_STATIC_CTYPES_LIBRARY_LOADER_ASYNC_CONTEXT_DISPATCH_REFERENCES = frozenset(
    {"ctypes.LibraryLoader.__aenter__", "ctypes.LibraryLoader.__aexit__"}
)
_STATIC_CTYPES_LIBRARY_LOADER_AWAIT_DISPATCH_REFERENCES = frozenset({"ctypes.LibraryLoader.__await__"})
_STATIC_CTYPES_LIBRARY_LOADER_MRO_DISPATCH_REFERENCES = frozenset({"ctypes.LibraryLoader.__mro_entries__"})
_STATIC_CTYPES_LIBRARY_LOADER_MATCH_DISPATCH_REFERENCES = frozenset(
    {
        "ctypes.LibraryLoader.__len__",
        "ctypes.LibraryLoader.__getitem__",
        "ctypes.LibraryLoader.keys",
        "ctypes.LibraryLoader.__eq__",
    }
)
_STATIC_CTYPES_LIBRARY_LOADER_DISPATCH_REFERENCES = (
    _STATIC_CTYPES_LIBRARY_LOADER_CONSTRUCTION_DISPATCH_REFERENCES
    | _STATIC_CTYPES_LIBRARY_LOADER_ATTRIBUTE_DISPATCH_REFERENCES
    | _STATIC_CTYPES_LIBRARY_LOADER_ITEM_DISPATCH_REFERENCES
    | _STATIC_CTYPES_LIBRARY_LOADER_LOAD_LIBRARY_DISPATCH_REFERENCES
    | _STATIC_CTYPES_LIBRARY_LOADER_DELETE_DISPATCH_REFERENCES
    | _STATIC_CTYPES_LIBRARY_LOADER_ITEM_STORE_DISPATCH_REFERENCES
    | _STATIC_CTYPES_LIBRARY_LOADER_ITEM_DELETE_DISPATCH_REFERENCES
    | _STATIC_CTYPES_LIBRARY_LOADER_TRUTH_DISPATCH_REFERENCES
    | _STATIC_CTYPES_LIBRARY_LOADER_CALL_DISPATCH_REFERENCES
    | _STATIC_CTYPES_LIBRARY_LOADER_GENERIC_PROTOCOL_DISPATCH_REFERENCES
)
_STATIC_UNCERTAIN_MEMBER_PREFIX = "<uncertain>:"
_STATIC_CANONICAL_MEMBER_PREFIX = "<canonical-member>:"
_STATIC_INERT_METHOD_PREFIX = "<inert-method>:"
_STATIC_INERT_VALUE_PREFIX = "<inert-value>:"
_STATIC_INERT_MEMBER_STATUS_PREFIX = "<inert-member-status>:"
_STATIC_INERT_CTYPES_LIBRARY_LOADER = f"{_STATIC_INERT_VALUE_PREFIX}ctypes.LibraryLoader"
_SYS_MODULES_BINDING_PREFIX = "<sys-modules>:"
_SYS_MODULES_NAMESPACE_ALIAS = "sys.modules"
_TRACKED_STATIC_MEMBER_REFERENCES = (
    _STATIC_OVERWRITABLE_HIGH_RISK_REFERENCES
    | _STATIC_TRUTHY_BUILTIN_REFERENCES
    | _STATIC_SIDE_EFFECT_FREE_BUILTIN_REFERENCES
    | _STATIC_DISPATCH_DECORATOR_REFERENCES
    | _STATIC_CLASS_CREATION_REFERENCES
    | _STATIC_MODULE_REGISTRY_REFERENCES
    | _STATIC_MODULE_TYPE_REFERENCES
    | _STATIC_MUTABLE_BUILTIN_HELPER_REFERENCES
    | _STATIC_CONTEXT_MANAGER_HELPER_REFERENCES
    | _STATIC_OPERATOR_ACCESSOR_HELPER_REFERENCES
    | _STATIC_CTYPES_LIBRARY_LOADER_DISPATCH_REFERENCES
)
_TRACKED_STATIC_MODULE_ROOTS = frozenset(
    reference.partition(".")[0] for reference in _TRACKED_STATIC_MEMBER_REFERENCES if "." in reference
)

# Map each high-risk call name to the rule code that best describes its risk
# category. SARIF consumers, dashboards, and per-rule severity overrides rely
# on accurate codes, so `os.system` must not be reported under `S104`
# (eval/exec) just because the scanner hard-coded a single fallback.
_HIGH_RISK_PYTHON_CALL_RULE_CODES: dict[str, str] = {
    "__import__": "S106",
    "builtins.__import__": "S106",
    "builtins.eval": "S104",
    "builtins.exec": "S104",
    "eval": "S104",
    "exec": "S104",
    "importlib.import_module": "S107",
    "pickle.load": "S213",
    "pickle.loads": "S213",
    **dict.fromkeys(_SUBPROCESS_PROCESS_EXECUTION_CALLS, "S103"),
    **dict.fromkeys(_OS_PROCESS_EXECUTION_CALLS, "S101"),
    **dict.fromkeys(_ASYNCIO_PROCESS_EXECUTION_CALLS, "S103"),
    **dict.fromkeys(_RUNPY_CODE_EXECUTION_CALLS, "S108"),
    **dict.fromkeys(_WEBBROWSER_LAUNCH_CALLS, "S109"),
    **dict.fromkeys(_CTYPES_NATIVE_LIBRARY_LOADING_CALLS, "S110"),
}
_HIGH_RISK_PYTHON_CALL_PREFIX_RULE_CODES: tuple[tuple[str, str], ...] = (
    ("subprocess.", "S103"),
    ("ctypes.LibraryLoader.", "S110"),
)
_FALLBACK_HIGH_RISK_RULE_CODE = "S104"
_HIGH_RISK_PYTHON_CALLS = frozenset(_HIGH_RISK_PYTHON_CALL_RULE_CODES)


def _strip_dunder_call_suffixes(reference_name: str) -> str:
    while reference_name.endswith(".__call__"):
        reference_name = reference_name.removesuffix(".__call__")
    return reference_name


def _localized_instance_root(root_name: str, local_name: str) -> str:
    return f"{root_name}@{local_name}"


def _is_localized_instance_root(root_name: str, base_root: str) -> bool:
    return root_name.startswith(f"{base_root}@")


def _is_ctypes_library_loader_object_root(root_name: str) -> bool:
    return root_name in _CTYPES_LIBRARY_LOADER_OBJECTS or any(
        _is_localized_instance_root(root_name, loader_root) for loader_root in _CTYPES_LIBRARY_LOADER_OBJECTS
    )


def _is_webbrowser_controller_root(root_name: str) -> bool:
    return root_name in _WEBBROWSER_CONTROLLER_FACTORIES or any(
        _is_localized_instance_root(root_name, controller_root) for controller_root in _WEBBROWSER_CONTROLLER_FACTORIES
    )


def _is_tracked_dynamic_instance_root(root_name: str) -> bool:
    return _is_webbrowser_controller_root(root_name) or _is_ctypes_library_loader_object_root(root_name)


def _split_ctypes_loader_reference(reference_name: str) -> tuple[str, str] | None:
    reference_name = _strip_dunder_call_suffixes(reference_name)
    for candidate_root in sorted(_CTYPES_LIBRARY_LOADER_OBJECTS, key=len, reverse=True):
        localized_prefix = f"{candidate_root}@"
        if reference_name.startswith(localized_prefix):
            suffix_start = reference_name.find(".", len(localized_prefix))
            if suffix_start == -1:
                return reference_name, ""
            return reference_name[:suffix_start], reference_name[suffix_start + 1 :]
        if reference_name == candidate_root:
            return candidate_root, ""
        if reference_name.startswith(f"{candidate_root}."):
            return candidate_root, reference_name[len(candidate_root) + 1 :]
    return None


def _ctypes_loader_attribute_load_name(reference_name: str) -> str | None:
    split_reference = _split_ctypes_loader_reference(reference_name)
    if split_reference is None:
        return None
    loader_root, suffix = split_reference
    if not suffix:
        return None
    library_name = suffix.split(".", maxsplit=1)[0]
    if (
        library_name.startswith("_")
        or library_name in _CTYPES_LIBRARY_LOADER_NON_LOADING_ATTRIBUTES
        or library_name in {"LoadLibrary", "__getitem__"}
    ):
        return None
    display_root = _CTYPES_LIBRARY_LOADER_DISPLAY_ROOTS.get(loader_root.split("@", maxsplit=1)[0], loader_root)
    return f"{display_root}.{library_name}"


def _ctypes_loader_overwritable_reference_name(reference_name: str) -> str | None:
    split_reference = _split_ctypes_loader_reference(reference_name)
    if split_reference is None:
        return None
    loader_root, suffix = split_reference
    if not suffix:
        return None
    member_name = suffix.split(".", maxsplit=1)[0]
    if (
        member_name.startswith("_") and member_name not in {"__getitem__", "__getattr__"}
    ) or member_name in _CTYPES_LIBRARY_LOADER_NON_LOADING_ATTRIBUTES:
        return None
    display_root = _CTYPES_LIBRARY_LOADER_DISPLAY_ROOTS.get(loader_root.split("@", maxsplit=1)[0], loader_root)
    return f"{display_root}.{member_name}"


def _webbrowser_controller_launch_call_name(reference_name: str) -> str | None:
    reference_name = _strip_dunder_call_suffixes(reference_name)
    root_name, separator, method_name = reference_name.rpartition(".")
    if not separator or not _is_webbrowser_controller_root(root_name):
        return None
    if method_name not in _WEBBROWSER_CONTROLLER_LAUNCH_METHODS:
        return None
    return f"webbrowser.{method_name}"


def _normalized_high_risk_python_call_name(name: str) -> str | None:
    stripped_name = _strip_dunder_call_suffixes(name)
    if stripped_name in _HIGH_RISK_PYTHON_CALLS or stripped_name.startswith("subprocess."):
        return stripped_name
    webbrowser_launch_name = _webbrowser_controller_launch_call_name(stripped_name)
    if webbrowser_launch_name is not None:
        return webbrowser_launch_name
    ctypes_load_name = _ctypes_loader_attribute_load_name(stripped_name)
    if ctypes_load_name is not None:
        return ctypes_load_name
    return None


def _has_static_overwritable_reference_prefix(name: str) -> bool:
    return any(
        name == reference_name or name.startswith(f"{reference_name}.")
        for reference_name in _STATIC_OVERWRITABLE_HIGH_RISK_REFERENCES
    )


def _is_overwritable_high_risk_reference(name: str) -> bool:
    return (
        name in _TRACKED_STATIC_MEMBER_REFERENCES
        or _webbrowser_controller_launch_call_name(name) is not None
        or _ctypes_loader_overwritable_reference_name(name) is not None
    )


def _is_dynamic_overwritable_high_risk_reference(name: str) -> bool:
    return (
        _webbrowser_controller_launch_call_name(name) is not None
        or _ctypes_loader_overwritable_reference_name(name) is not None
    )


def _ctypes_loader_member_load_names(resolved_roots: frozenset[str], attr_name: str | None) -> frozenset[str]:
    library_name = attr_name or _CTYPES_DYNAMIC_LIBRARY_NAME
    if attr_name is not None and (
        attr_name.startswith("_")
        or attr_name in _CTYPES_LIBRARY_LOADER_NON_LOADING_ATTRIBUTES
        or attr_name in {"LoadLibrary", "__getitem__"}
    ):
        return frozenset()
    return frozenset(
        f"{resolved_root}.{library_name}"
        for resolved_root in resolved_roots
        if _is_ctypes_library_loader_object_root(resolved_root)
    )


def _split_env_shebang_command(value: str) -> str | None:
    try:
        split_parts = shlex.split(value)
    except ValueError:
        split_parts = value.split()
    if not split_parts:
        return None
    return split_parts[0].rsplit("/", 1)[-1].lower()


def _rule_code_for_high_risk_call(call_name: str) -> str:
    """Return the rule code that most accurately describes ``call_name``."""
    direct = _HIGH_RISK_PYTHON_CALL_RULE_CODES.get(call_name)
    if direct is not None:
        return direct
    if _webbrowser_controller_launch_call_name(call_name) is not None:
        return "S109"
    if _ctypes_loader_attribute_load_name(call_name) is not None:
        return "S110"
    for prefix, code in _HIGH_RISK_PYTHON_CALL_PREFIX_RULE_CODES:
        if call_name.startswith(prefix):
            return code
    return _FALLBACK_HIGH_RISK_RULE_CODE


@dataclass(frozen=True)
class HighRiskPythonCall:
    """A high-risk call resolved from an archive member's Python source."""

    name: str
    rule_code: str


class PythonArchiveMemberParseError(Exception):
    """Raised when Python member security analysis cannot parse source."""


_AliasValue = frozenset[str] | None
_AliasScope = dict[str, _AliasValue]
_AliasScopes = list[_AliasScope]
_GLOBALS_MAPPING_ALIAS = "<globals mapping>"
_MODULE_LOCALS_MAPPING_ALIAS = "<module locals mapping>"
_LOCAL_NAMESPACE_MAPPING_ALIAS = "<local mapping>"
_TRACKED_MODULE_NAMESPACE_ALIASES = frozenset({_GLOBALS_MAPPING_ALIAS, _MODULE_LOCALS_MAPPING_ALIAS})
_MODULE_NAMESPACE_WRITE_PREFIX = "<module namespace write>."
_STATIC_DICT_ITEM_ALIAS_PREFIX = "<static dict item>"
_STATIC_DICT_COMPLETE_ALIAS = "<static dict complete>"
_STATIC_DICT_UNCERTAIN_ALIAS = "<static dict uncertain>"
_STATIC_SEQUENCE_ITEM_ALIAS_PREFIX = "<static sequence item>"
_STATIC_SEQUENCE_COMPLETE_ALIAS = "<static sequence complete>"
_STATIC_SEQUENCE_UNCERTAIN_ALIAS = "<static sequence uncertain>"
_STATIC_MUTABLE_SEQUENCE_ALIAS = "<static mutable sequence>"
_STATIC_CONTAINER_ID_ALIAS_PREFIX = "<static container id>"
_STATIC_CONTAINER_POSSIBLE_ITEM_ALIAS_PREFIX = "<static container possible item>"
_OPERATOR_ATTRGETTER_ALIAS_PREFIX = "<operator.attrgetter>"
_OPERATOR_ITEMGETTER_ALIAS_PREFIX = "<operator.itemgetter>"
_OPERATOR_METHODCALLER_ALIAS_PREFIX = "<operator.methodcaller>"
_OPERATOR_METHODCALLER_DYNAMIC_ACCESS_METHODS = frozenset(
    {"__delitem__", "__getattribute__", "__getitem__", "__setitem__", "get", "insert", "pop", "setdefault"}
)
_STATIC_CONTAINER_MUTATION_METHODS = frozenset(
    {
        "__delitem__",
        "__iadd__",
        "__imul__",
        "__ior__",
        "__setitem__",
        "append",
        "clear",
        "extend",
        "insert",
        "pop",
        "popitem",
        "remove",
        "reverse",
        "setdefault",
        "sort",
        "update",
    }
)


def is_executable_archive_member_name(member_name: str) -> bool:
    """Return True when an archive member name has an executable/native-library suffix."""
    return executable_archive_member_name_rule_code(member_name) is not None


def executable_archive_member_name_rule_code(member_name: str) -> str | None:
    """Return the executable rule code implied by an archive member name."""
    normalized_name = member_name.lower()
    if normalized_name.endswith((".exe", ".dll", ".scr", ".com")):
        return "S501"
    if normalized_name.endswith(".so") or _VERSIONED_SHARED_OBJECT_SUFFIX_RE.search(normalized_name):
        return "S502"
    if normalized_name.endswith(".dylib"):
        return "S503"
    if normalized_name.endswith((".sh", ".bash")):
        return "S504"
    if normalized_name.endswith((".bat", ".cmd")):
        return "S505"
    if normalized_name.endswith(".ps1"):
        return "S506"
    return None


def _looks_like_portable_executable(
    prefix: bytes,
    *,
    read_prefix: Callable[[int], bytes] | None = None,
) -> ExecutableArchiveMemberProbeOutcome:
    if not prefix.startswith(b"MZ"):
        return "absent"
    if b"This program cannot be run in DOS mode" in prefix[:512]:
        return "detected"
    if len(prefix) < _PORTABLE_EXECUTABLE_MIN_HEADER_OFFSET:
        return "absent"

    pe_offset = int.from_bytes(
        prefix[_PORTABLE_EXECUTABLE_POINTER_OFFSET : _PORTABLE_EXECUTABLE_POINTER_OFFSET + 4],
        "little",
        signed=False,
    )
    if pe_offset < _PORTABLE_EXECUTABLE_MIN_HEADER_OFFSET:
        return "absent"
    if pe_offset > _PORTABLE_EXECUTABLE_MAX_HEADER_OFFSET:
        return "incomplete"

    if pe_offset + len(_PORTABLE_EXECUTABLE_SIGNATURE) <= len(prefix):
        if prefix[pe_offset : pe_offset + len(_PORTABLE_EXECUTABLE_SIGNATURE)] == _PORTABLE_EXECUTABLE_SIGNATURE:
            return "detected"
        return "absent"

    if read_prefix is None:
        return "absent"

    expanded_prefix = read_prefix(pe_offset + len(_PORTABLE_EXECUTABLE_SIGNATURE))
    if (
        len(expanded_prefix) >= pe_offset + len(_PORTABLE_EXECUTABLE_SIGNATURE)
        and expanded_prefix[pe_offset : pe_offset + len(_PORTABLE_EXECUTABLE_SIGNATURE)]
        == _PORTABLE_EXECUTABLE_SIGNATURE
    ):
        return "detected"
    return "absent"


def _looks_like_macho_fat_binary(prefix: bytes) -> bool:
    magic = prefix[:4]
    if magic not in _MACHO_FAT_MAGICS or len(prefix) < 8:
        return False

    byteorder: Literal["big", "little"] = (
        "big" if magic in {_MACHO_FAT_MAGIC_32_BE, _MACHO_FAT_MAGIC_64_BE} else "little"
    )
    arch_count = int.from_bytes(prefix[4:8], byteorder, signed=False)
    if not 1 <= arch_count <= 128:
        return False

    arch_entry_size = 32 if magic in {_MACHO_FAT_MAGIC_64_BE, _MACHO_FAT_MAGIC_64_LE} else 20
    return len(prefix) >= 8 + (arch_count * arch_entry_size)


def probe_executable_archive_member_signature(
    read_prefix: Callable[[int], bytes],
) -> ExecutableArchiveMemberProbeOutcome:
    """Classify strong executable signatures without reading beyond the bounded PE budget."""
    prefix = read_prefix(_EXECUTABLE_ARCHIVE_MEMBER_MAGIC_READ_BYTES)
    if prefix.startswith(_EXECUTABLE_ARCHIVE_MEMBER_MAGIC_PREFIXES):
        return "detected"
    if _looks_like_macho_fat_binary(prefix):
        return "detected"
    return _looks_like_portable_executable(prefix, read_prefix=read_prefix)


def has_executable_archive_member_signature(read_prefix: Callable[[int], bytes]) -> bool:
    """Return True when a bounded prefix reader exposes a confirmed executable signature."""
    return probe_executable_archive_member_signature(read_prefix) == "detected"


def probe_executable_archive_member_content(path: str) -> ExecutableArchiveMemberProbeOutcome:
    """Classify executable bytes in an extracted archive member."""
    try:
        with open(path, "rb") as member_file:

            def read_prefix(limit: int) -> bytes:
                member_file.seek(0)
                return member_file.read(limit)

            return probe_executable_archive_member_signature(read_prefix)
    except OSError:
        return "absent"


def is_executable_archive_member_content(path: str) -> bool:
    """Return True when a member begins with a confirmed executable signature."""
    return probe_executable_archive_member_content(path) == "detected"


def _shebang_command_name(source_bytes: bytes) -> str | None:
    if not source_bytes.startswith(b"#!"):
        return None
    first_line = source_bytes.splitlines()[0][2:].decode("utf-8", errors="ignore").strip()
    if not first_line:
        return None
    try:
        parts = shlex.split(first_line)
    except ValueError:
        parts = first_line.split()
    if not parts:
        return None

    command = parts[0].rsplit("/", 1)[-1].lower()
    if command != "env":
        return command

    index = 1
    while index < len(parts):
        token = parts[index]
        if token in {"-S", "--split-string"}:
            if index + 1 >= len(parts):
                return None
            return _split_env_shebang_command(parts[index + 1])
        if token.startswith("--split-string="):
            return _split_env_shebang_command(token.split("=", 1)[1])
        if token.startswith("-S") and token != "-S":
            return _split_env_shebang_command(token[2:])
        if token in _ENV_SHEBANG_OPTIONS_WITH_ARGUMENT:
            index += 2
            continue
        if token == "--" or token.startswith("--unset=") or token.startswith("--chdir="):
            index += 1
            continue
        if token.startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
            index += 1
            continue
        return token.rsplit("/", 1)[-1].lower()
    return None


def _python_member_has_non_python_shebang(source_bytes: bytes) -> bool:
    if not source_bytes.startswith(b"#!"):
        return False
    command = _shebang_command_name(source_bytes)
    return command is None or _PYTHON_SHEBANG_COMMAND_RE.fullmatch(command) is None


def _probe_python_archive_member_executable_content(path: str) -> ExecutableArchiveMemberProbeOutcome:
    try:
        with open(path, "rb") as member_file:
            prefix_cache = member_file.read(_EXECUTABLE_ARCHIVE_MEMBER_MAGIC_READ_BYTES)
            if prefix_cache.startswith(b"#!"):
                return "detected" if _python_member_has_non_python_shebang(prefix_cache) else "absent"

            def read_prefix(limit: int) -> bytes:
                nonlocal prefix_cache
                if limit <= len(prefix_cache) or not prefix_cache.startswith(b"MZ"):
                    return prefix_cache[:limit]
                member_file.seek(0)
                expanded_prefix = member_file.read(limit)
                if len(expanded_prefix) > len(prefix_cache):
                    prefix_cache = expanded_prefix
                return prefix_cache[:limit]

            return probe_executable_archive_member_signature(read_prefix)
    except OSError:
        return "absent"


def executable_archive_member_content_rule_code(path: str) -> str | None:
    """Return the executable rule code implied by an archive member's content."""
    try:
        with open(path, "rb") as member_file:
            prefix_cache = member_file.read(_EXECUTABLE_ARCHIVE_MEMBER_MAGIC_READ_BYTES)

            def read_prefix(limit: int) -> bytes:
                nonlocal prefix_cache
                if limit <= len(prefix_cache) or not prefix_cache.startswith(b"MZ"):
                    return prefix_cache[:limit]
                member_file.seek(0)
                expanded_prefix = member_file.read(limit)
                if len(expanded_prefix) > len(prefix_cache):
                    prefix_cache = expanded_prefix
                return prefix_cache[:limit]

            return _executable_archive_member_content_rule_code(prefix_cache, read_prefix=read_prefix)
    except OSError:
        return None


def executable_archive_member_content_rule_code_from_bytes(content: bytes) -> str | None:
    """Return the executable rule code implied by bounded member bytes."""
    return _executable_archive_member_content_rule_code(content)


def _executable_archive_member_content_rule_code(
    prefix: bytes,
    *,
    read_prefix: Callable[[int], bytes] | None = None,
) -> str | None:
    if _looks_like_portable_executable(prefix, read_prefix=read_prefix) == "detected":
        return "S501"
    if prefix.startswith(b"\x7fELF"):
        return "S502"
    if prefix.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")):
        return "S503"
    if _looks_like_macho_fat_binary(prefix):
        return "S503"
    if prefix.startswith(b"#!"):
        return "S504"
    return None


def executable_archive_member_rule_code(member_name: str, path: str) -> str | None:
    """Return the best executable rule code for an archive member."""
    return executable_archive_member_content_rule_code(path) or executable_archive_member_name_rule_code(member_name)


def is_python_archive_member_name(member_name: str) -> bool:
    """Return True when an archive member name looks like Python source."""
    return member_name.lower().endswith(_PYTHON_ARCHIVE_MEMBER_SUFFIXES)


def _resolve_call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _resolve_call_name(node.value)
        if parent is None:
            return None
        return f"{parent}.{node.attr}"
    return None


def _lookup_bound_alias(name: str, alias_scopes: _AliasScopes) -> tuple[_AliasValue, bool]:
    for aliases in reversed(alias_scopes):
        if name in aliases:
            return aliases[name], True
        module_write_name = f"{_MODULE_NAMESPACE_WRITE_PREFIX}{name}"
        if module_write_name in aliases:
            return aliases[module_write_name], True
    return None, False


def _resolve_aliases(name: str, alias_scopes: _AliasScopes) -> _AliasValue:
    aliases, found = _lookup_bound_alias(name, alias_scopes)
    if found:
        return aliases
    return frozenset({name})


def _apply_aliases(call_name: str, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    parts = call_name.split(".")
    for prefix_length in range(len(parts), 0, -1):
        prefix = ".".join(parts[:prefix_length])
        aliases, found = _lookup_bound_alias(prefix, alias_scopes)
        if not found:
            continue
        if aliases is None:
            return None
        suffix = ".".join(parts[prefix_length:])
        if not suffix:
            return aliases
        resolved_aliases = frozenset(f"{alias}.{suffix}" for alias in aliases)
        rebound_aliases: set[str] = set()
        saw_rebound = False
        for resolved_alias in resolved_aliases:
            rebound, rebound_found = _lookup_bound_alias(resolved_alias, alias_scopes)
            if not rebound_found:
                rebound_aliases.add(resolved_alias)
                continue
            saw_rebound = True
            if rebound is not None:
                rebound_aliases.update(rebound)
        if saw_rebound:
            return frozenset(rebound_aliases) or None
        return resolved_aliases
    return frozenset({call_name})


def _apply_aliases_to_names(names: frozenset[str], alias_scopes: _AliasScopes) -> frozenset[str] | None:
    resolved_names: set[str] = set()
    for name in names:
        aliases = _apply_aliases(name, alias_scopes)
        if aliases is not None:
            resolved_names.update(aliases)
    return frozenset(resolved_names) or None


def _canonical_ctypes_loader_type_aliases(names: frozenset[str] | None) -> frozenset[str]:
    if names is None:
        return frozenset()
    loader_types = names & _CTYPES_LIBRARY_LOADER_TYPES
    if loader_types:
        return loader_types
    if names & _CTYPES_LIBRARY_LOADER_TYPE_ALIASES:
        return frozenset({"ctypes.CDLL"})
    return frozenset()


def _normalize_implicit_builtins_names(
    names: frozenset[str] | None, alias_scopes: _AliasScopes
) -> frozenset[str] | None:
    if names is None or _resolve_aliases("__builtins__", alias_scopes) != frozenset({"__builtins__"}):
        return names
    normalized_names: set[str] = set()
    for name in names:
        if name == "object" and not _lookup_bound_alias(name, alias_scopes)[1]:
            normalized_names.update(_apply_aliases("builtins.object", alias_scopes) or frozenset())
        elif name == "__builtins__" or name.startswith("__builtins__."):
            normalized_names.add(f"builtins{name.removeprefix('__builtins__')}")
        elif "." not in name and not _lookup_bound_alias(name, alias_scopes)[1]:
            builtin_names, builtin_found = _lookup_bound_alias(f"builtins.{name}", alias_scopes)
            if builtin_found:
                if isinstance(builtin_names, frozenset):
                    normalized_names.update(builtin_names)
            else:
                normalized_names.add(name)
        else:
            normalized_names.add(name)
    return frozenset(normalized_names) or None


_MAX_STATIC_STRING_LENGTH = 1024
_MAX_STATIC_STRING_PARTS = 256


def _resolve_static_string(node: ast.AST) -> str | None:
    """Resolve bounded compile-time string expressions used in attribute lookups."""
    pending = [node]
    parts: list[str] = []
    part_count = 0
    total_length = 0

    while pending:
        current = pending.pop()
        if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            pending.extend([current.right, current.left])
            continue
        if not isinstance(current, ast.Constant) or not isinstance(current.value, str):
            return None

        part_count += 1
        if part_count > _MAX_STATIC_STRING_PARTS:
            return None
        total_length += len(current.value)
        if total_length > _MAX_STATIC_STRING_LENGTH:
            return None
        parts.append(current.value)

    return "".join(parts)


def _resolve_static_integer(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return int(node.value)
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, (ast.UAdd, ast.USub))
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, int)
    ):
        value = int(node.operand.value)
        return value if isinstance(node.op, ast.UAdd) else -value
    return None


_MAX_STATIC_ITEM_KEY_BYTES = 1024
_MAX_STATIC_ITEM_KEY_TUPLE_ITEMS = 64
_MAX_STATIC_ITEM_KEY_DEPTH = 8
_MAX_STATIC_CONTAINER_UPDATE_ITEMS = 256
_StaticItemKey = str | int | float | complex | bool | bytes | None | EllipsisType | tuple["_StaticItemKey", ...]


def _resolve_static_item_key(
    node: ast.AST,
    *,
    _depth: int = 0,
) -> tuple[bool, _StaticItemKey]:
    if _depth > _MAX_STATIC_ITEM_KEY_DEPTH:
        return False, None
    string_value = _resolve_static_string(node)
    if string_value is not None:
        return True, string_value
    if isinstance(node, ast.Constant):
        if node.value is None or node.value is Ellipsis:
            return True, node.value
        if isinstance(node.value, bytes):
            return (True, node.value) if len(node.value) <= _MAX_STATIC_ITEM_KEY_BYTES else (False, None)
        if isinstance(node.value, (bool, int, float, complex)):
            if isinstance(node.value, (float, complex)) and not (
                math.isfinite(node.value.real) and math.isfinite(node.value.imag)
            ):
                return False, None
            return True, node.value
    if isinstance(node, ast.Tuple):
        if len(node.elts) > _MAX_STATIC_ITEM_KEY_TUPLE_ITEMS:
            return False, None
        resolved_items = tuple(_resolve_static_item_key(element, _depth=_depth + 1) for element in node.elts)
        if not all(resolved for resolved, _item in resolved_items):
            return False, None
        return True, tuple(item for _resolved, item in resolved_items)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
        left_resolved, left = _resolve_static_item_key(node.left, _depth=_depth + 1)
        right_resolved, right = _resolve_static_item_key(node.right, _depth=_depth + 1)
        if (
            left_resolved
            and right_resolved
            and isinstance(left, (int, float, complex))
            and isinstance(right, (int, float, complex))
            and not isinstance(left, bool)
            and not isinstance(right, bool)
        ):
            value = left + right if isinstance(node.op, ast.Add) else left - right
            if isinstance(value, (float, complex)) and not (math.isfinite(value.real) and math.isfinite(value.imag)):
                return False, None
            return True, value
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, (ast.UAdd, ast.USub))
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, (int, float, complex))
    ):
        value = node.operand.value if isinstance(node.op, ast.UAdd) else -node.operand.value
        if isinstance(value, (float, complex)) and not (math.isfinite(value.real) and math.isfinite(value.imag)):
            return False, None
        return True, value
    return False, None


def _resolve_static_namespace_update_items(node: ast.AST) -> list[tuple[str, ast.expr]] | None:
    """Resolve bounded literal mapping updates accepted by dict.update and dict.__ior__."""
    if isinstance(node, ast.Dict):
        updates: list[tuple[str, ast.expr]] = []
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None:
                if not isinstance(value, ast.Dict):
                    return None
                expanded = _resolve_static_namespace_update_items(value)
                if expanded is None:
                    return None
                updates.extend(expanded)
            else:
                resolved_key = _resolve_static_string(key)
                if resolved_key is None:
                    return None
                updates.append((resolved_key, value))
            if len(updates) > _MAX_STATIC_CONTAINER_UPDATE_ITEMS:
                return None
        return updates
    if isinstance(node, (ast.List, ast.Tuple)):
        updates = []
        for element in node.elts:
            if not isinstance(element, (ast.List, ast.Tuple)) or len(element.elts) != 2:
                return None
            resolved_key = _resolve_static_string(element.elts[0])
            if resolved_key is None:
                return None
            updates.append((resolved_key, element.elts[1]))
            if len(updates) > _MAX_STATIC_CONTAINER_UPDATE_ITEMS:
                return None
        return updates
    return None


def _resolve_static_container_update_items(node: ast.AST) -> list[tuple[_StaticItemKey, ast.expr]] | None:
    """Resolve bounded literal mapping updates while preserving non-string keys."""
    if isinstance(node, ast.Dict):
        updates: list[tuple[_StaticItemKey, ast.expr]] = []
        for key_node, value_node in zip(node.keys, node.values, strict=True):
            if key_node is None:
                if not isinstance(value_node, ast.Dict):
                    return None
                expanded = _resolve_static_container_update_items(value_node)
                if expanded is None:
                    return None
                updates.extend(expanded)
            else:
                key_resolved, key = _resolve_static_item_key(key_node)
                if not key_resolved:
                    return None
                updates.append((key, value_node))
            if len(updates) > _MAX_STATIC_CONTAINER_UPDATE_ITEMS:
                return None
        return updates
    if isinstance(node, (ast.List, ast.Tuple)):
        updates = []
        for element in node.elts:
            if not isinstance(element, (ast.List, ast.Tuple)) or len(element.elts) != 2:
                return None
            key_resolved, key = _resolve_static_item_key(element.elts[0])
            if not key_resolved:
                return None
            updates.append((key, element.elts[1]))
            if len(updates) > _MAX_STATIC_CONTAINER_UPDATE_ITEMS:
                return None
        return updates
    return None


def _encode_operator_accessor_name(prefix: str, *fields: str) -> str:
    return f"{prefix}{''.join(f'{len(field)}:{field}' for field in fields)}"


def _decode_operator_accessor_name(name: str, prefix: str, field_count: int) -> tuple[str, ...] | None:
    if not name.startswith(prefix):
        return None
    remainder = name[len(prefix) :]
    fields: list[str] = []
    for _index in range(field_count):
        length_text, separator, value = remainder.partition(":")
        if not separator or not length_text.isdecimal():
            return None
        field_length = int(length_text)
        if field_length > len(value):
            return None
        fields.append(value[:field_length])
        remainder = value[field_length:]
    if _strip_dunder_call_suffixes(remainder):
        return None
    return tuple(fields)


def _decode_operator_accessor_fields(name: str, prefix: str) -> tuple[str, ...] | None:
    if not name.startswith(prefix):
        return None
    remainder = name[len(prefix) :]
    fields: list[str] = []
    while remainder and not remainder.startswith(".__call__"):
        length_text, separator, value = remainder.partition(":")
        if not separator or not length_text.isdecimal():
            return None
        field_length = int(length_text)
        if field_length > len(value):
            return None
        fields.append(value[:field_length])
        remainder = value[field_length:]
    if not fields or _strip_dunder_call_suffixes(remainder):
        return None
    return tuple(fields)


def _encode_operator_itemgetter_key(key: _StaticItemKey) -> str:
    if key is None:
        return "n:"
    if key is Ellipsis:
        return "e:"
    if isinstance(key, str):
        return f"s:{key}"
    if isinstance(key, bytes):
        return f"y:{key.hex()}"
    if isinstance(key, bool):
        return f"b:{int(key)}"
    if isinstance(key, int):
        return f"i:{key}"
    if isinstance(key, float):
        return f"f:{key!r}"
    if isinstance(key, complex):
        return _encode_operator_accessor_name("c:", repr(key.real), repr(key.imag))
    return _encode_operator_accessor_name("t:", *(_encode_operator_itemgetter_key(item) for item in key))


def _decode_operator_itemgetter_key(field: str) -> tuple[bool, _StaticItemKey]:
    kind, separator, value = field.partition(":")
    if not separator:
        return False, None
    if kind == "n" and not value:
        return True, None
    if kind == "e" and not value:
        return True, Ellipsis
    if kind == "s":
        return True, value
    if kind == "y":
        if len(value) > _MAX_STATIC_ITEM_KEY_BYTES * 2:
            return False, None
        try:
            return True, bytes.fromhex(value)
        except ValueError:
            return False, None
    if kind == "b" and value in {"0", "1"}:
        return True, value == "1"
    if kind == "i":
        try:
            return True, int(value)
        except ValueError:
            return False, None
    if kind == "f":
        try:
            decoded_float = float(value)
        except ValueError:
            return False, None
        return (True, decoded_float) if math.isfinite(decoded_float) else (False, None)
    if kind == "c":
        fields = _decode_operator_accessor_fields(value, "")
        if fields is None or len(fields) != 2:
            return False, None
        try:
            decoded_complex = complex(float(fields[0]), float(fields[1]))
        except ValueError:
            return False, None
        return (
            (True, decoded_complex)
            if math.isfinite(decoded_complex.real) and math.isfinite(decoded_complex.imag)
            else (False, None)
        )
    if kind == "t":
        if not value:
            return True, ()
        fields = _decode_operator_accessor_fields(value, "")
        if fields is None or len(fields) > _MAX_STATIC_ITEM_KEY_TUPLE_ITEMS:
            return False, None
        decoded_items = tuple(_decode_operator_itemgetter_key(item) for item in fields)
        if not all(resolved for resolved, _item in decoded_items):
            return False, None
        return True, tuple(item for _resolved, item in decoded_items)
    return False, None


def _resolve_operator_itemgetter_key(node: ast.AST) -> tuple[bool, _StaticItemKey]:
    return _resolve_static_item_key(node)


def _resolve_static_container_update_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> list[tuple[_StaticItemKey, _AliasValue]] | None:
    literal_updates = _resolve_static_container_update_items(node)
    if literal_updates is not None:
        return [
            (
                key,
                _resolve_static_reference_names(
                    value_node,
                    alias_scopes,
                    allow_module_locals_mapping=allow_module_locals_mapping,
                    allow_local_namespace_mapping=allow_local_namespace_mapping,
                ),
            )
            for key, value_node in literal_updates
        ]

    aliases = _resolve_static_reference_names(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if aliases is None or _STATIC_DICT_COMPLETE_ALIAS not in aliases or _STATIC_DICT_UNCERTAIN_ALIAS in aliases:
        return None
    decoded_updates: dict[_StaticItemKey, set[str]] = {}
    for alias in aliases:
        decoded = _decode_operator_accessor_name(alias, _STATIC_DICT_ITEM_ALIAS_PREFIX, 2)
        if decoded is None:
            continue
        key_resolved, key = _decode_operator_itemgetter_key(decoded[0])
        if not key_resolved:
            return None
        decoded_updates.setdefault(key, set())
        if decoded[1]:
            decoded_updates[key].add(decoded[1])
    return [(key, frozenset(value_names) or None) for key, value_names in decoded_updates.items()]


def _is_static_non_string(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and not isinstance(node.value, str)


def _keyword_is_empty_static_kwargs(keyword: ast.keyword) -> bool:
    return (
        keyword.arg is None
        and isinstance(keyword.value, ast.Dict)
        and not keyword.value.keys
        and not keyword.value.values
    )


def _keywords_are_all_empty_static_kwargs(keywords: list[ast.keyword]) -> bool:
    """True when ``keywords`` carries no runtime keyword (only empty ``**{}``).

    ``setattr``/``delattr`` are positional-only, but Python still accepts a
    trailing empty ``**{}`` unpack, which is equivalent to passing no keyword.
    """
    return all(_keyword_is_empty_static_kwargs(keyword) for keyword in keywords)


def _static_keyword_arguments(keywords: list[ast.keyword]) -> dict[str, ast.AST] | None:
    values: dict[str, ast.AST] = {}
    for keyword in keywords:
        if _keyword_is_empty_static_kwargs(keyword):
            continue
        entry_values: dict[str, ast.AST] = {}
        if keyword.arg is not None:
            entry_values[keyword.arg] = keyword.value
        elif isinstance(keyword.value, ast.Dict):
            for key_node, value_node in zip(keyword.value.keys, keyword.value.values, strict=True):
                if key_node is None:
                    return None
                key = _resolve_static_string(key_node)
                if key is None:
                    return None
                entry_values[key] = value_node
        else:
            return None
        if values.keys() & entry_values.keys():
            return None
        values.update(entry_values)
    return values


def _static_call_keyword_arguments(
    keywords: list[ast.keyword],
    allowed_keywords: frozenset[str],
) -> dict[str, ast.AST] | None:
    keyword_values = _static_keyword_arguments(keywords)
    if keyword_values is None or not set(keyword_values) <= allowed_keywords:
        return None
    return keyword_values


def _single_static_call_argument(
    args: list[ast.expr],
    keywords: list[ast.keyword],
    *,
    keyword_name: str,
) -> ast.AST | None:
    meaningful_keywords = [keyword for keyword in keywords if not _keyword_is_empty_static_kwargs(keyword)]
    expanded_args: list[ast.AST] = []
    for argument in args:
        if isinstance(argument, ast.Starred):
            value = argument.value
            if not isinstance(value, (ast.Tuple, ast.List)):
                return None
            expanded_args.extend(value.elts)
            continue
        expanded_args.append(argument)
    if len(expanded_args) == 1 and not meaningful_keywords:
        return expanded_args[0]
    if expanded_args or len(meaningful_keywords) != 1:
        return None

    keyword_values = _static_keyword_arguments(meaningful_keywords)
    if keyword_values is None or set(keyword_values) != {keyword_name}:
        return None
    return keyword_values[keyword_name]


def _resolve_getattr_call_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    # Resolve literal names and compile-time string concatenation. Runtime-built
    # names still fall outside this static member analysis by design.
    if isinstance(node, ast.Attribute) and node.attr == "__call__":
        return _resolve_getattr_call_names(
            node.value,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )

    if not isinstance(node, ast.Call):
        return None

    unbound_getattribute_names = _resolve_unbound_getattribute_call_names(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if unbound_getattribute_names is not None:
        return unbound_getattribute_names

    helper_name = _resolve_call_name(node.func)
    if helper_name is not None:
        resolved_helper_names = _apply_aliases(helper_name, alias_scopes)
    else:
        resolved_helper_names = None
        if not isinstance(node.func, ast.Call):
            resolved_helper_names = _resolve_static_reference_names(
                node.func,
                alias_scopes,
                allow_module_locals_mapping=allow_module_locals_mapping,
                allow_local_namespace_mapping=allow_local_namespace_mapping,
            )
        if resolved_helper_names is None:
            resolved_helper_names = _resolve_getattr_call_names(
                node.func,
                alias_scopes,
                allow_module_locals_mapping=allow_module_locals_mapping,
                allow_local_namespace_mapping=allow_local_namespace_mapping,
            )
    if resolved_helper_names is None:
        return None

    normalized_helper_names: set[str] = set()
    for resolved_helper_name in resolved_helper_names:
        while resolved_helper_name.endswith(".__call__"):
            resolved_helper_name = resolved_helper_name.removesuffix(".__call__")
        normalized_helper_names.add(resolved_helper_name)
    keyword_values = _static_keyword_arguments(node.keywords)
    expanded_args = _expanded_static_call_args(node) if keyword_values == {} else None

    if normalized_helper_names & {"object.__getattribute__", "builtins.object.__getattribute__"}:
        if expanded_args is None or len(expanded_args) != 2:
            return None
        resolved_target_roots = _resolve_static_reference_names(
            expanded_args[0],
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        attr_name = _resolve_static_string(expanded_args[1])
        if resolved_target_roots is None:
            return None
        if attr_name in {"__getitem__", "__getattr__", "LoadLibrary"}:
            loader_method_roots = frozenset(
                resolved_root
                for resolved_root in resolved_target_roots
                if _is_ctypes_library_loader_object_root(resolved_root)
            )
            if loader_method_roots:
                return _apply_aliases_to_names(
                    frozenset(f"{resolved_target_root}.{attr_name}" for resolved_target_root in loader_method_roots),
                    alias_scopes,
                )
        if attr_name is None:
            return None
        resolved_target_roots = frozenset(
            root for root in resolved_target_roots if not _is_ctypes_library_loader_object_root(root)
        )
        if not resolved_target_roots:
            return None
        return _apply_aliases_to_names(
            frozenset(f"{resolved_target_root}.{attr_name}" for resolved_target_root in resolved_target_roots),
            alias_scopes,
        )

    getattr_accessor_names = frozenset(
        root
        for normalized_helper_name in normalized_helper_names
        for root in (normalized_helper_name.rsplit(".", maxsplit=1)[0],)
        if normalized_helper_name.endswith(".__getattr__") and _is_ctypes_library_loader_object_root(root)
    )
    getattribute_accessor_names = frozenset(
        root
        for normalized_helper_name in normalized_helper_names
        for root in (normalized_helper_name.rsplit(".", maxsplit=1)[0],)
        if normalized_helper_name.endswith(".__getattribute__") and not _is_ctypes_library_loader_object_root(root)
    )
    accessor_names = getattr_accessor_names | getattribute_accessor_names
    if accessor_names:
        if node.keywords and not getattr_accessor_names:
            return None
        attr_node = _single_static_call_argument(node.args, node.keywords, keyword_name="name")
        if attr_node is None:
            return None
        if _is_static_non_string(attr_node):
            return None
        attr_name = _resolve_static_string(attr_node)
        if attr_name is None and not getattr_accessor_names:
            return None
        resolved_names: set[str] = set(_ctypes_loader_member_load_names(getattr_accessor_names, attr_name))
        if attr_name is None:
            return frozenset(resolved_names) or None
        getattribute_names = _apply_aliases_to_names(
            frozenset(f"{target_root}.{attr_name}" for target_root in getattribute_accessor_names),
            alias_scopes,
        )
        getattribute_names = _augment_noncanonical_module_member_names(
            getattribute_names, getattribute_accessor_names, attr_name, alias_scopes
        )
        if getattribute_names is not None:
            resolved_names.update(getattribute_names)
        return frozenset(resolved_names) or None

    has_getattr_helper = bool(normalized_helper_names & {"getattr", "builtins.getattr"})
    has_hasattr_helper = bool(normalized_helper_names & {"hasattr", "builtins.hasattr"})
    if not (has_getattr_helper or has_hasattr_helper):
        return None

    expected_arg_counts = {2, 3} if has_getattr_helper else {2}
    if expanded_args is None or len(expanded_args) not in expected_arg_counts:
        return None
    target_root_node = expanded_args[0]
    attr_name_node = expanded_args[1]

    if _is_static_non_string(attr_name_node):
        return None
    attr_name = _resolve_static_string(attr_name_node)
    resolved_target_roots = _resolve_static_reference_names(
        target_root_node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if resolved_target_roots is None:
        return None
    if has_hasattr_helper and not has_getattr_helper:
        ctypes_member_names = _ctypes_loader_member_load_names(resolved_target_roots, attr_name)
        if not ctypes_member_names:
            return None
        return _apply_aliases_to_names(ctypes_member_names, alias_scopes)
    if attr_name is None:
        return _ctypes_loader_member_load_names(resolved_target_roots, attr_name) or None
    return _augment_noncanonical_module_member_names(
        _apply_aliases_to_names(
            frozenset(f"{resolved_target_root}.{attr_name}" for resolved_target_root in resolved_target_roots),
            alias_scopes,
        ),
        resolved_target_roots,
        attr_name,
        alias_scopes,
    )


def _resolve_unbound_getattribute_call_names(
    node: ast.Call,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    if (
        not isinstance(node.func, ast.Attribute)
        or node.func.attr not in {"__getattribute__", "__getattr__", "__getitem__"}
        or len(node.args) != 2
        or node.keywords
    ):
        return None
    if _is_static_non_string(node.args[1]):
        return None
    attr_name = _resolve_static_string(node.args[1])
    target_roots = _resolve_static_reference_names(
        node.args[0],
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if target_roots is None:
        return None

    class_owner = node.func.value
    owner_roots: frozenset[str] | None = None
    if isinstance(class_owner, ast.Attribute) and class_owner.attr == "__class__":
        owner_roots = _resolve_static_reference_names(
            class_owner.value,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
    elif isinstance(class_owner, ast.Call) and _canonical_type_call_argument(class_owner, alias_scopes) is not None:
        owner_roots = _resolve_static_reference_names(
            class_owner.args[0],
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
    else:
        resolved_class_names = _resolve_static_reference_names(
            class_owner,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        if resolved_class_names and resolved_class_names & _CTYPES_LIBRARY_LOADER_CONSTRUCTORS:
            owner_roots = target_roots
    if owner_roots is None:
        return None
    compatible_roots = frozenset(
        root
        for root in target_roots & owner_roots
        if root in _TRACKED_STATIC_MODULE_ROOTS or _is_ctypes_library_loader_object_root(root)
    )
    if not compatible_roots:
        return None
    if node.func.attr in {"__getattr__", "__getitem__"}:
        return _apply_aliases_to_names(_ctypes_loader_member_load_names(compatible_roots, attr_name), alias_scopes)
    if attr_name is None:
        return None
    return _apply_aliases_to_names(frozenset(f"{root}.{attr_name}" for root in compatible_roots), alias_scopes)


def _canonical_type_call_argument(node: ast.Call, alias_scopes: _AliasScopes) -> ast.AST | None:
    if len(node.args) != 1 or node.keywords:
        return None
    helper_name = _resolve_call_name(node.func)
    if helper_name is None:
        return None
    if helper_name == "type" and not _lookup_bound_alias("type", alias_scopes)[1]:
        resolved_helper_names = _resolve_aliases("builtins.type", alias_scopes)
    else:
        resolved_helper_names = _apply_aliases(helper_name, alias_scopes)
    return node.args[0] if resolved_helper_names == frozenset({"builtins.type"}) else None


def _augment_noncanonical_module_member_names(
    resolved_names: frozenset[str] | None,
    target_roots: frozenset[str],
    attr_name: str,
    alias_scopes: _AliasScopes,
) -> frozenset[str] | None:
    uncertain_names = frozenset(
        f"{target_root}.{attr_name}"
        for target_root in target_roots
        if target_root in _TRACKED_STATIC_MODULE_ROOTS
        and _resolve_aliases(f"{target_root}.__class__", alias_scopes) != frozenset({f"{target_root}.__class__"})
        and _is_overwritable_high_risk_reference(f"{target_root}.{attr_name}")
    )
    if uncertain_names:
        return frozenset({*(resolved_names or frozenset()), *uncertain_names})
    return resolved_names


def _resolve_namespace_mapping_roots(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    """Resolve statically selected namespace mappings relevant to risky lookups."""
    implicit_builtins_roots = _resolve_globals_builtins_mapping_roots(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if implicit_builtins_roots is not None:
        return implicit_builtins_roots

    mapping_aliases = _resolve_globals_mapping_alias(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if mapping_aliases is not None:
        return mapping_aliases

    for operator_accessor_names in (
        _resolve_operator_attrgetter_call_result_names(
            node,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        ),
        _resolve_operator_methodcaller_dynamic_access_names(
            node,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        ),
    ):
        namespace_roots = frozenset(
            name.removesuffix(".__dict__")
            for name in operator_accessor_names or frozenset()
            if name.endswith(".__dict__")
        )
        if namespace_roots:
            return namespace_roots

    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        resolved_module_names = _resolve_static_reference_names(
            node.value,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        tracked_module_roots = frozenset(
            name for name in resolved_module_names or frozenset() if name in _TRACKED_STATIC_MODULE_ROOTS
        )
        if tracked_module_roots:
            return tracked_module_roots
        nested_roots = _resolve_namespace_mapping_roots(
            node.value,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        if nested_roots is not None:
            return nested_roots

    mapping_name = _resolve_call_name(node)
    if mapping_name is not None:
        resolved_mapping_names = _apply_aliases(mapping_name, alias_scopes)
        if resolved_mapping_names is not None:
            if mapping_name == "__builtins__" and resolved_mapping_names == frozenset({"__builtins__"}):
                return frozenset({"builtins"})
            resolved_mapping_names = _normalize_implicit_builtins_names(resolved_mapping_names, alias_scopes)
            if resolved_mapping_names is None:
                return None
            if _SYS_MODULES_NAMESPACE_ALIAS in resolved_mapping_names:
                return frozenset({_SYS_MODULES_NAMESPACE_ALIAS})
            namespace_roots = frozenset(
                name.removesuffix(".__dict__") for name in resolved_mapping_names if name.endswith(".__dict__")
            )
            if namespace_roots:
                return namespace_roots

    getattr_names = _resolve_getattr_call_names(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if getattr_names is not None:
        getattr_names = _normalize_implicit_builtins_names(getattr_names, alias_scopes)
        if getattr_names is None:
            return None
        namespace_roots = frozenset(
            name.removesuffix(".__dict__") for name in getattr_names if name.endswith(".__dict__")
        )
        if namespace_roots:
            return namespace_roots

    lookup_names = _resolve_namespace_mapping_lookup_names(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if lookup_names is not None:
        namespace_roots = frozenset(
            name.removesuffix(".__dict__") for name in lookup_names if name == "builtins" or name.endswith(".__dict__")
        )
        if namespace_roots:
            return namespace_roots

    if not isinstance(node, ast.Call):
        return None

    resolved_helper_names = _resolve_static_reference_names(
        node.func,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if resolved_helper_names is None or not (resolved_helper_names & {"vars", "builtins.vars"}):
        return None
    if len(node.args) != 1 or node.keywords:
        return None

    target_root = _resolve_call_name(node.args[0])
    resolved_roots = _apply_aliases(target_root, alias_scopes) if target_root is not None else None
    if resolved_roots is None:
        return None
    return _normalize_implicit_builtins_names(resolved_roots, alias_scopes)


def _resolve_globals_mapping_alias(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    """Resolve statically tracked mappings returned by globals(), locals(), or vars()."""
    if isinstance(node, ast.Call):
        if node.args or node.keywords:
            return None
        helper_name = _resolve_call_name(node.func)
        resolved_helpers = _apply_aliases(helper_name, alias_scopes) if helper_name is not None else None
        if resolved_helpers is not None and resolved_helpers & {"globals", "builtins.globals"}:
            return frozenset({_GLOBALS_MAPPING_ALIAS})
        locals_helpers = {"locals", "builtins.locals", "vars", "builtins.vars"}
        if resolved_helpers is None or not (resolved_helpers & locals_helpers):
            return None
        if allow_module_locals_mapping:
            return frozenset({_MODULE_LOCALS_MAPPING_ALIAS})
        if allow_local_namespace_mapping:
            return frozenset({_LOCAL_NAMESPACE_MAPPING_ALIAS})
        return None

    reference_name = _resolve_call_name(node)
    if reference_name is None:
        return None
    resolved_names = _apply_aliases(reference_name, alias_scopes)
    if resolved_names is None:
        return None
    namespace_aliases = resolved_names & _TRACKED_MODULE_NAMESPACE_ALIASES
    return namespace_aliases or None


_NAMESPACE_LOOKUP_METHODS = frozenset({"get", "__getitem__", "pop", "setdefault"})
_NAMESPACE_LOOKUP_METHODS_WITH_DEFAULTS = frozenset({"get", "pop", "setdefault"})
_NAMESPACE_LOOKUP_DESCRIPTORS = frozenset(
    f"{prefix}.{method}" for prefix in ("dict", "builtins.dict") for method in _NAMESPACE_LOOKUP_METHODS
)
_NAMESPACE_WRITE_METHODS = frozenset({"__setitem__", "setdefault"})
_NAMESPACE_MUTATION_METHODS = _NAMESPACE_WRITE_METHODS | frozenset({"pop", "__delitem__"})
_NAMESPACE_MUTATION_DESCRIPTORS = frozenset(
    f"{prefix}.{method}" for prefix in ("dict", "builtins.dict") for method in _NAMESPACE_MUTATION_METHODS
)
_NAMESPACE_MAPPING_METHODS = _NAMESPACE_LOOKUP_METHODS | _NAMESPACE_WRITE_METHODS | frozenset({"update"})


def _resolve_module_namespace_key_names(
    key: str, alias_scopes: _AliasScopes, *, allow_module_locals_mapping: bool
) -> tuple[frozenset[str] | None, bool]:
    """Resolve a literal key selected from the current module namespace."""
    write_name = f"{_MODULE_NAMESPACE_WRITE_PREFIX}{key}"
    for scope in reversed(alias_scopes):
        if write_name in scope:
            return scope[write_name], True
    visible_scopes = alias_scopes if allow_module_locals_mapping else alias_scopes[:1]
    for scope in reversed(visible_scopes):
        if key not in scope:
            continue
        names = scope[key]
        if key == "__builtins__" and names == frozenset({"__builtins__"}):
            return frozenset({"builtins", "builtins.__dict__"}), True
        return names, True
    if key == "__builtins__":
        return frozenset({"builtins", "builtins.__dict__"}), True
    return frozenset({key}), False


def _resolve_local_namespace_key_names(key: str, alias_scopes: _AliasScopes) -> tuple[frozenset[str] | None, bool]:
    current_scope = alias_scopes[-1]
    if key not in current_scope:
        return None, False
    return current_scope[key], True


def _resolve_mapping_root_item_names(
    root: str,
    key: str,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
) -> tuple[frozenset[str] | None, bool]:
    if root in _TRACKED_MODULE_NAMESPACE_ALIASES:
        return _resolve_module_namespace_key_names(
            key,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
        )
    if root == _LOCAL_NAMESPACE_MAPPING_ALIAS:
        return _resolve_local_namespace_key_names(key, alias_scopes)

    member_name = f"{root}.{key}"
    member_names, member_is_bound = _lookup_bound_alias(member_name, alias_scopes)
    if member_is_bound:
        return member_names, member_names != frozenset()
    return frozenset({member_name}), member_name in (
        _TRACKED_STATIC_MEMBER_REFERENCES | _STATIC_KNOWN_PRESENT_MODULE_REFERENCES
    )


def _resolve_globals_builtins_mapping_roots(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    """Resolve the implicit builtins mapping read from a tracked namespace."""
    mapping_node: ast.AST
    key_node: ast.AST
    if isinstance(node, ast.Subscript):
        mapping_node = node.value
        key_node = node.slice
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _NAMESPACE_LOOKUP_METHODS
        and node.args
        and not node.keywords
    ):
        if node.func.attr == "__getitem__" and len(node.args) != 1:
            return None
        if node.func.attr in _NAMESPACE_LOOKUP_METHODS_WITH_DEFAULTS and len(node.args) not in {1, 2}:
            return None
        mapping_node = node.func.value
        key_node = node.args[0]
    else:
        return None

    if _resolve_static_string(key_node) != "__builtins__":
        return None
    mapping_aliases = _resolve_globals_mapping_alias(
        mapping_node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if mapping_aliases is None:
        return None
    if mapping_aliases & {_LOCAL_NAMESPACE_MAPPING_ALIAS}:
        selected_names, _guaranteed = _resolve_local_namespace_key_names("__builtins__", alias_scopes)
    elif mapping_aliases & _TRACKED_MODULE_NAMESPACE_ALIASES:
        selected_names, _guaranteed = _resolve_module_namespace_key_names(
            "__builtins__", alias_scopes, allow_module_locals_mapping=allow_module_locals_mapping
        )
    else:
        return None
    if selected_names is None:
        return None
    roots = frozenset(name.removesuffix(".__dict__") for name in selected_names if name.endswith(".__dict__"))
    return roots or None


def _resolve_namespace_mapping_lookup_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    """Resolve bounded literal callable retrieval from a tracked namespace."""
    if isinstance(node, ast.Attribute) and node.attr == "__call__":
        return _resolve_namespace_mapping_lookup_names(
            node.value,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )

    mapping_node: ast.AST | None = None
    key_node: ast.AST
    default_node: ast.AST | None = None
    resolved_roots: frozenset[str] | None = None
    lookup_methods: frozenset[str] = frozenset()
    if isinstance(node, ast.Subscript):
        mapping_node = node.value
        key_node = node.slice
        lookup_methods = frozenset({"__getitem__"})
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _NAMESPACE_LOOKUP_METHODS
        and node.args
        and not node.keywords
    ):
        descriptor_name = _resolve_call_name(node.func)
        resolved_descriptor_names = (
            _apply_aliases(descriptor_name, alias_scopes) if descriptor_name is not None else None
        )
        is_descriptor = bool(resolved_descriptor_names and resolved_descriptor_names & _NAMESPACE_LOOKUP_DESCRIPTORS)
        argument_offset = 1 if is_descriptor else 0
        expected_lengths = {2} if node.func.attr == "__getitem__" and is_descriptor else {1}
        if node.func.attr in _NAMESPACE_LOOKUP_METHODS_WITH_DEFAULTS:
            expected_lengths = {2, 3} if is_descriptor else {1, 2}
        if len(node.args) not in expected_lengths:
            return None
        mapping_node = node.args[0] if is_descriptor else node.func.value
        key_node = node.args[argument_offset]
        if node.func.attr in _NAMESPACE_LOOKUP_METHODS_WITH_DEFAULTS and len(node.args) == max(expected_lengths):
            default_node = node.args[argument_offset + 1]
        lookup_methods = frozenset({node.func.attr})
    elif isinstance(node, ast.Call) and node.args and not node.keywords:
        method_name = _resolve_call_name(node.func)
        resolved_method_names = _apply_aliases(method_name, alias_scopes) if method_name is not None else None
        normalized_method_names = set()
        for resolved_method_name in resolved_method_names or ():
            while resolved_method_name.endswith(".__call__"):
                resolved_method_name = resolved_method_name.removesuffix(".__call__")
            normalized_method_names.add(resolved_method_name)
        getattr_names = _resolve_getattr_call_names(
            node.func,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        for getattr_name in getattr_names or ():
            while getattr_name.endswith(".__call__"):
                getattr_name = getattr_name.removesuffix(".__call__")
            normalized_method_names.add(getattr_name)
        descriptor_methods = {
            method
            for method in _NAMESPACE_LOOKUP_METHODS
            if normalized_method_names & {f"dict.{method}", f"builtins.dict.{method}"}
        }
        valid_descriptor_methods = {
            method
            for method in descriptor_methods
            if (method == "__getitem__" and len(node.args) == 2)
            or (method in _NAMESPACE_LOOKUP_METHODS_WITH_DEFAULTS and len(node.args) in {2, 3})
        }
        if valid_descriptor_methods:
            resolved_roots = _resolve_namespace_mapping_roots(
                node.args[0],
                alias_scopes,
                allow_module_locals_mapping=allow_module_locals_mapping,
                allow_local_namespace_mapping=allow_local_namespace_mapping,
            )
            if resolved_roots is None:
                return None
            key_node = node.args[1]
            lookup_methods = frozenset(valid_descriptor_methods)
            if len(node.args) == 3:
                default_node = node.args[2]
        else:
            resolved_mapping_method_roots = {
                (method, name.removesuffix(f".__dict__.{method}"))
                for name in normalized_method_names
                for method in _NAMESPACE_LOOKUP_METHODS
                if name.endswith(f".__dict__.{method}")
            }
            valid_methods = {
                method
                for method, _root in resolved_mapping_method_roots
                if (method == "__getitem__" and len(node.args) == 1)
                or (method in _NAMESPACE_LOOKUP_METHODS_WITH_DEFAULTS and len(node.args) in {1, 2})
            }
            if not valid_methods:
                return None
            resolved_roots = _normalize_implicit_builtins_names(
                frozenset(root for method, root in resolved_mapping_method_roots if method in valid_methods),
                alias_scopes,
            )
            if not resolved_roots:
                return None
            key_node = node.args[0]
            lookup_methods = frozenset(valid_methods)
            if len(node.args) == 2:
                default_node = node.args[1]
    else:
        return None

    if resolved_roots is None and mapping_node is not None:
        resolved_roots = _resolve_namespace_mapping_roots(
            mapping_node,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
    default_names: frozenset[str] | None = None
    if default_node is not None and lookup_methods & _NAMESPACE_LOOKUP_METHODS_WITH_DEFAULTS:
        default_names = _resolve_static_reference_names(
            default_node,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
    key = _resolve_static_string(key_node)
    if resolved_roots is None or key is None:
        return default_names
    selected_names: set[str] = set()
    selected_value_guaranteed = bool(resolved_roots)
    for resolved_root in resolved_roots:
        member_names, guaranteed = _resolve_mapping_root_item_names(
            resolved_root,
            key,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
        )
        if member_names is not None:
            selected_names.update(member_names)
        selected_value_guaranteed = selected_value_guaranteed and guaranteed
    resolved_names = frozenset(selected_names)
    if default_names is not None and not selected_value_guaranteed:
        resolved_names = resolved_names | default_names
    return resolved_names


def _resolve_webbrowser_controller_factory_roots(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    if not isinstance(node, ast.Call):
        return None
    resolved_func_names = _resolve_static_reference_names(
        node.func,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if resolved_func_names is None:
        return None
    controller_factories = resolved_func_names & _WEBBROWSER_CONTROLLER_FACTORIES
    return controller_factories or None


def _expanded_static_call_args(node: ast.Call) -> list[ast.expr] | None:
    expanded_args: list[ast.expr] = []
    for arg in node.args:
        if isinstance(arg, ast.Starred):
            if not isinstance(arg.value, (ast.Tuple, ast.List)):
                return None
            expanded_args.extend(arg.value.elts)
        else:
            expanded_args.append(arg)
    return expanded_args


def _operator_accessor_target_node(node: ast.Call) -> ast.AST | None:
    if not _keywords_are_all_empty_static_kwargs(node.keywords):
        return None
    expanded_args = _expanded_static_call_args(node)
    if expanded_args is None or len(expanded_args) != 1:
        return None
    return expanded_args[0]


def _resolve_operator_accessor_factory_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    if not isinstance(node, ast.Call):
        return None
    helper_names = _resolve_static_reference_names(
        node.func,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    normalized_helper_names = frozenset(
        _strip_dunder_call_suffixes(helper_name) for helper_name in helper_names or frozenset()
    )
    expanded_args = _expanded_static_call_args(node)
    if expanded_args is None:
        return None

    accessor_names: set[str] = set()
    if (
        "operator.attrgetter" in normalized_helper_names
        and _keywords_are_all_empty_static_kwargs(node.keywords)
        and expanded_args
    ):
        attr_names = tuple(
            attr_name for arg in expanded_args if (attr_name := _resolve_static_string(arg)) is not None and attr_name
        )
        if len(attr_names) == len(expanded_args):
            accessor_names.add(_encode_operator_accessor_name(_OPERATOR_ATTRGETTER_ALIAS_PREFIX, *attr_names))

    if (
        "operator.itemgetter" in normalized_helper_names
        and _keywords_are_all_empty_static_kwargs(node.keywords)
        and expanded_args
    ):
        resolved_item_keys = tuple(_resolve_operator_itemgetter_key(arg) for arg in expanded_args)
        if all(resolved for resolved, _item_key in resolved_item_keys):
            accessor_names.add(
                _encode_operator_accessor_name(
                    _OPERATOR_ITEMGETTER_ALIAS_PREFIX,
                    *(_encode_operator_itemgetter_key(item_key) for _resolved, item_key in resolved_item_keys),
                )
            )

    if "operator.methodcaller" in normalized_helper_names and expanded_args:
        method_name = _resolve_static_string(expanded_args[0])
        if method_name:
            if method_name in {"update", "__ior__"} and len(expanded_args) <= 2:
                updates = (
                    _resolve_static_container_update_names(
                        expanded_args[1],
                        alias_scopes,
                        allow_module_locals_mapping=allow_module_locals_mapping,
                        allow_local_namespace_mapping=allow_local_namespace_mapping,
                    )
                    if len(expanded_args) == 2
                    else []
                )
                if updates is not None and (
                    method_name == "update" or _keywords_are_all_empty_static_kwargs(node.keywords)
                ):
                    precise_updates = True
                    keyword_names: set[str] = set()
                    for keyword in node.keywords:
                        if keyword.arg is not None:
                            if keyword.arg in keyword_names:
                                precise_updates = False
                                break
                            keyword_names.add(keyword.arg)
                            value_names = _resolve_static_reference_names(
                                keyword.value,
                                alias_scopes,
                                allow_module_locals_mapping=allow_module_locals_mapping,
                                allow_local_namespace_mapping=allow_local_namespace_mapping,
                            )
                            updates.append((keyword.arg, value_names))
                            if len(updates) > _MAX_STATIC_CONTAINER_UPDATE_ITEMS:
                                precise_updates = False
                                break
                            continue
                        expanded_updates = _resolve_static_container_update_names(
                            keyword.value,
                            alias_scopes,
                            allow_module_locals_mapping=allow_module_locals_mapping,
                            allow_local_namespace_mapping=allow_local_namespace_mapping,
                        )
                        if expanded_updates is None:
                            precise_updates = False
                            break
                        expanded_keyword_names: set[str] = set()
                        for key, _value_names in expanded_updates:
                            if not isinstance(key, str):
                                precise_updates = False
                                break
                            expanded_keyword_names.add(key)
                        if not precise_updates or keyword_names & expanded_keyword_names:
                            precise_updates = False
                            break
                        keyword_names.update(expanded_keyword_names)
                        updates.extend(expanded_updates)
                        if len(updates) > _MAX_STATIC_CONTAINER_UPDATE_ITEMS:
                            precise_updates = False
                            break
                    if precise_updates and updates:
                        final_updates: dict[_StaticItemKey, _AliasValue] = {}
                        for key, value_names in updates:
                            final_updates[key] = value_names
                        for key, value_names in final_updates.items():
                            for value_name in value_names or frozenset({""}):
                                accessor_names.add(
                                    _encode_operator_accessor_name(
                                        _OPERATOR_METHODCALLER_ALIAS_PREFIX,
                                        method_name,
                                        _encode_operator_itemgetter_key(key),
                                        value_name,
                                    )
                                )
                        return frozenset(accessor_names) or None
            if method_name in _OPERATOR_METHODCALLER_DYNAMIC_ACCESS_METHODS and not (
                _keywords_are_all_empty_static_kwargs(node.keywords)
            ):
                return frozenset(accessor_names) or None
            dynamic_method_arg_counts = {
                "__delitem__": {2},
                "__getattribute__": {2},
                "__getitem__": {2},
                "__setitem__": {3},
                "append": {2},
                "get": {2, 3},
                "insert": {3},
                "pop": {1, 2, 3},
                "setdefault": {2, 3},
            }
            if (
                method_name in dynamic_method_arg_counts
                and len(expanded_args) not in dynamic_method_arg_counts[method_name]
            ):
                return frozenset(accessor_names) or None
            lookup_name = ""
            fallback_names: frozenset[str] | None = None
            if method_name in _OPERATOR_METHODCALLER_DYNAMIC_ACCESS_METHODS and len(expanded_args) >= 2:
                lookup_resolved, lookup_key = _resolve_static_item_key(expanded_args[1])
                if lookup_resolved:
                    lookup_name = _encode_operator_itemgetter_key(lookup_key)
            if (method_name in _NAMESPACE_LOOKUP_METHODS_WITH_DEFAULTS and len(expanded_args) >= 3) or (
                method_name in {"__setitem__", "insert"} and len(expanded_args) == 3
            ):
                fallback_names = _resolve_static_reference_names(
                    expanded_args[2],
                    alias_scopes,
                    allow_module_locals_mapping=allow_module_locals_mapping,
                    allow_local_namespace_mapping=allow_local_namespace_mapping,
                )
            elif method_name == "append" and len(expanded_args) == 2:
                fallback_names = _resolve_static_reference_names(
                    expanded_args[1],
                    alias_scopes,
                    allow_module_locals_mapping=allow_module_locals_mapping,
                    allow_local_namespace_mapping=allow_local_namespace_mapping,
                )
            for fallback_name in fallback_names or frozenset({""}):
                accessor_names.add(
                    _encode_operator_accessor_name(
                        _OPERATOR_METHODCALLER_ALIAS_PREFIX, method_name, lookup_name, fallback_name
                    )
                )

    return frozenset(accessor_names) or None


def _resolve_static_member_names(
    target_roots: frozenset[str] | None,
    member_name: str,
    alias_scopes: _AliasScopes,
) -> frozenset[str] | None:
    if target_roots is None or not member_name:
        return None
    resolved_names = _apply_aliases_to_names(
        frozenset(f"{target_root}.{member_name}" for target_root in target_roots),
        alias_scopes,
    )
    return _augment_noncanonical_module_member_names(resolved_names, target_roots, member_name, alias_scopes)


def _resolve_static_container_item_names(
    node: ast.AST,
    key: _StaticItemKey,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> tuple[frozenset[str] | None, bool] | None:
    selected_node: ast.AST | None = None
    if isinstance(node, ast.Dict):
        updates = _resolve_static_container_update_items(node)
        if updates is None:
            return None
        for resolved_key, value_node in reversed(updates):
            if resolved_key == key:
                selected_node = value_node
                break
        if selected_node is None:
            return None, False
    elif isinstance(node, (ast.List, ast.Tuple)) and isinstance(key, (bool, int)):
        sequence_index = int(key)
        if not -len(node.elts) <= sequence_index < len(node.elts):
            return None, False
        selected_node = node.elts[sequence_index]
    else:
        container_aliases = _resolve_static_reference_names(
            node,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        if container_aliases is None:
            return None
        container_kinds = [(_STATIC_DICT_ITEM_ALIAS_PREFIX, _STATIC_DICT_COMPLETE_ALIAS, _STATIC_DICT_UNCERTAIN_ALIAS)]
        if isinstance(key, (bool, int)):
            container_kinds.append(
                (
                    _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX,
                    _STATIC_SEQUENCE_COMPLETE_ALIAS,
                    _STATIC_SEQUENCE_UNCERTAIN_ALIAS,
                )
            )
        matching_kinds = [
            (alias_prefix, complete_alias in container_aliases and uncertain_alias not in container_aliases)
            for alias_prefix, complete_alias, uncertain_alias in container_kinds
            if complete_alias in container_aliases or uncertain_alias in container_aliases
        ]
        if not matching_kinds:
            return None
        selected_names: set[str] = set()
        selected_value_guaranteed = False
        if any(not kind_is_complete for _alias_prefix, kind_is_complete in matching_kinds):
            for alias in container_aliases:
                decoded = _decode_operator_accessor_name(alias, _STATIC_CONTAINER_POSSIBLE_ITEM_ALIAS_PREFIX, 1)
                if decoded is not None and decoded[0]:
                    selected_names.update(_apply_aliases(decoded[0], alias_scopes) or frozenset())
        for alias_prefix, kind_is_complete in matching_kinds:
            for alias in container_aliases:
                decoded = _decode_operator_accessor_name(alias, alias_prefix, 2)
                if decoded is None:
                    continue
                decoded_resolved, decoded_key = _decode_operator_itemgetter_key(decoded[0])
                if not decoded_resolved or decoded_key != key:
                    continue
                selected_value_guaranteed = selected_value_guaranteed or kind_is_complete
                if decoded[1]:
                    selected_names.update(_apply_aliases(decoded[1], alias_scopes) or frozenset())
        if not selected_value_guaranteed and isinstance(key, str):
            container_internal_prefixes = (
                _STATIC_DICT_ITEM_ALIAS_PREFIX,
                _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX,
                _STATIC_CONTAINER_POSSIBLE_ITEM_ALIAS_PREFIX,
            )
            container_markers = {
                _STATIC_DICT_COMPLETE_ALIAS,
                _STATIC_DICT_UNCERTAIN_ALIAS,
                _STATIC_SEQUENCE_COMPLETE_ALIAS,
                _STATIC_SEQUENCE_UNCERTAIN_ALIAS,
            }
            alternate_roots = frozenset(
                "builtins" if alias == "__builtins__" else alias
                for alias in container_aliases
                if alias not in container_markers and not alias.startswith(container_internal_prefixes)
            )
            selected_names.update(
                _resolve_static_member_names(alternate_roots or None, key, alias_scopes) or frozenset()
            )
        return frozenset(selected_names) or None, selected_value_guaranteed
    return (
        _resolve_static_reference_names(
            selected_node,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        ),
        True,
    )


def _resolve_static_container_aliases(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    entries: dict[_StaticItemKey, ast.expr]
    item_alias_prefix: str
    complete_alias: str
    if isinstance(node, ast.Dict):
        entries = {}
        updates = _resolve_static_container_update_items(node)
        if updates is None:
            return None
        for key, value_node in updates:
            entries[key] = value_node
        item_alias_prefix = _STATIC_DICT_ITEM_ALIAS_PREFIX
        complete_alias = _STATIC_DICT_COMPLETE_ALIAS
    elif isinstance(node, (ast.List, ast.Tuple)):
        entries = dict(enumerate(node.elts))
        entries.update({index - len(node.elts): value_node for index, value_node in enumerate(node.elts)})
        item_alias_prefix = _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX
        complete_alias = _STATIC_SEQUENCE_COMPLETE_ALIAS
    else:
        return None

    aliases = {complete_alias}
    for key, value_node in entries.items():
        value_names = _resolve_static_reference_names(
            value_node,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        for value_name in value_names or frozenset({""}):
            aliases.add(
                _encode_operator_accessor_name(
                    item_alias_prefix,
                    _encode_operator_itemgetter_key(key),
                    value_name,
                )
            )
    return frozenset(aliases)


def _resolve_operator_itemgetter_target_names(
    target_node: ast.AST,
    key: _StaticItemKey,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    literal_lookup = _resolve_static_container_item_names(
        target_node,
        key,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if literal_lookup is not None:
        return literal_lookup[0]
    if not isinstance(key, str):
        return None
    mapping_roots = _resolve_namespace_mapping_roots(
        target_node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    selected_names: set[str] = set()
    for mapping_root in mapping_roots or frozenset():
        member_names, _guaranteed = _resolve_mapping_root_item_names(
            mapping_root,
            key,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
        )
        selected_names.update(member_names or frozenset())
    return frozenset(selected_names) or None


def _operator_accessor_field_groups(accessor_names: frozenset[str] | None, prefix: str) -> frozenset[tuple[str, ...]]:
    return frozenset(
        decoded
        for accessor_name in accessor_names or frozenset()
        if (decoded := _decode_operator_accessor_fields(accessor_name, prefix)) is not None
    )


def _operator_attrgetter_member_names(accessor_names: frozenset[str] | None) -> frozenset[str]:
    return frozenset(
        fields[0]
        for fields in _operator_accessor_field_groups(accessor_names, _OPERATOR_ATTRGETTER_ALIAS_PREFIX)
        if len(fields) == 1
    )


def _operator_itemgetter_keys(accessor_names: frozenset[str] | None) -> frozenset[_StaticItemKey]:
    keys: set[_StaticItemKey] = set()
    for fields in _operator_accessor_field_groups(accessor_names, _OPERATOR_ITEMGETTER_ALIAS_PREFIX):
        if len(fields) != 1:
            continue
        resolved, key = _decode_operator_itemgetter_key(fields[0])
        if resolved:
            keys.add(key)
    return frozenset(keys)


def _operator_methodcaller_fields(accessor_names: frozenset[str] | None) -> frozenset[tuple[str, str, str]]:
    fields: set[tuple[str, str, str]] = set()
    for accessor_name in accessor_names or frozenset():
        decoded = _decode_operator_accessor_name(accessor_name, _OPERATOR_METHODCALLER_ALIAS_PREFIX, 3)
        if decoded is not None:
            fields.add((decoded[0], decoded[1], decoded[2]))
    return frozenset(fields)


def _resolve_operator_attrgetter_call_result_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    if not isinstance(node, ast.Call):
        return None
    target_node = _operator_accessor_target_node(node)
    if target_node is None:
        return None
    attr_names = _operator_attrgetter_member_names(
        _resolve_static_reference_names(
            node.func,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
    )
    if not attr_names:
        return None
    target_roots = _resolve_static_reference_names(
        target_node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    resolved_names: set[str] = set()
    for attr_name in attr_names:
        resolved_names.update(_resolve_static_member_names(target_roots, attr_name, alias_scopes) or frozenset())
    return frozenset(resolved_names) or None


def _resolve_operator_itemgetter_call_result_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    if not isinstance(node, ast.Call):
        return None
    target_node = _operator_accessor_target_node(node)
    if target_node is None:
        return None
    item_keys = _operator_itemgetter_keys(
        _resolve_static_reference_names(
            node.func,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
    )
    if not item_keys:
        return None
    resolved_names: set[str] = set()
    for item_key in item_keys:
        resolved_names.update(
            _resolve_operator_itemgetter_target_names(
                target_node,
                item_key,
                alias_scopes,
                allow_module_locals_mapping=allow_module_locals_mapping,
                allow_local_namespace_mapping=allow_local_namespace_mapping,
            )
            or frozenset()
        )
    return frozenset(resolved_names) or None


def _resolve_operator_accessor_sequence_item_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    if (
        not isinstance(node, ast.Subscript)
        or not isinstance(node.value, ast.Call)
        or _resolve_static_integer(node.slice) is None
    ):
        return None
    target_node = _operator_accessor_target_node(node.value)
    if target_node is None:
        return None
    accessor_names = _resolve_static_reference_names(
        node.value.func,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    selected_names: set[str] = set()
    sequence_index = _resolve_static_integer(node.slice)
    if sequence_index is None:
        return None
    target_roots = _resolve_static_reference_names(
        target_node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    for fields in _operator_accessor_field_groups(accessor_names, _OPERATOR_ATTRGETTER_ALIAS_PREFIX):
        if len(fields) <= 1 or not -len(fields) <= sequence_index < len(fields):
            continue
        selected_names.update(_resolve_static_member_names(target_roots, fields[sequence_index], alias_scopes) or ())
    for fields in _operator_accessor_field_groups(accessor_names, _OPERATOR_ITEMGETTER_ALIAS_PREFIX):
        if len(fields) <= 1 or not -len(fields) <= sequence_index < len(fields):
            continue
        item_key_resolved, item_key = _decode_operator_itemgetter_key(fields[sequence_index])
        if not item_key_resolved:
            continue
        selected_names.update(
            _resolve_operator_itemgetter_target_names(
                target_node,
                item_key,
                alias_scopes,
                allow_module_locals_mapping=allow_module_locals_mapping,
                allow_local_namespace_mapping=allow_local_namespace_mapping,
            )
            or ()
        )
    return frozenset(selected_names) or None


def _resolve_operator_accessor_unpacking_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    expected_count: int,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> tuple[frozenset[str] | None, ...] | None:
    if not isinstance(node, ast.Call):
        return None
    target_node = _operator_accessor_target_node(node)
    if target_node is None:
        return None
    accessor_names = _resolve_static_reference_names(
        node.func,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    attr_field_groups = _operator_accessor_field_groups(accessor_names, _OPERATOR_ATTRGETTER_ALIAS_PREFIX)
    if len(attr_field_groups) == 1:
        fields = next(iter(attr_field_groups))
        if len(fields) == expected_count:
            target_roots = _resolve_static_reference_names(
                target_node,
                alias_scopes,
                allow_module_locals_mapping=allow_module_locals_mapping,
                allow_local_namespace_mapping=allow_local_namespace_mapping,
            )
            return tuple(_resolve_static_member_names(target_roots, field, alias_scopes) for field in fields)
    item_field_groups = _operator_accessor_field_groups(accessor_names, _OPERATOR_ITEMGETTER_ALIAS_PREFIX)
    if len(item_field_groups) == 1:
        fields = next(iter(item_field_groups))
        if len(fields) == expected_count:
            item_keys = tuple(_decode_operator_itemgetter_key(field) for field in fields)
            if all(resolved for resolved, _item_key in item_keys):
                return tuple(
                    _resolve_operator_itemgetter_target_names(
                        target_node,
                        item_key,
                        alias_scopes,
                        allow_module_locals_mapping=allow_module_locals_mapping,
                        allow_local_namespace_mapping=allow_local_namespace_mapping,
                    )
                    for _resolved, item_key in item_keys
                )
    return None


def _static_sequence_aliases_from_resolved_items(
    resolved_items: tuple[frozenset[str] | None, ...],
) -> frozenset[str]:
    aliases = {_STATIC_SEQUENCE_COMPLETE_ALIAS}
    item_count = len(resolved_items)
    for index, resolved_names in enumerate(resolved_items):
        for sequence_index in (index, index - item_count):
            for resolved_name in resolved_names or frozenset({""}):
                aliases.add(
                    _encode_operator_accessor_name(
                        _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX,
                        _encode_operator_itemgetter_key(sequence_index),
                        resolved_name,
                    )
                )
    return frozenset(aliases)


def _resolve_operator_accessor_result_sequence_aliases(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    if not isinstance(node, ast.Call):
        return None
    target_node = _operator_accessor_target_node(node)
    if target_node is None:
        return None
    accessor_names = _resolve_static_reference_names(
        node.func,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )

    attr_field_groups = _operator_accessor_field_groups(accessor_names, _OPERATOR_ATTRGETTER_ALIAS_PREFIX)
    if len(attr_field_groups) == 1:
        fields = next(iter(attr_field_groups))
        if len(fields) > 1:
            target_roots = _resolve_static_reference_names(
                target_node,
                alias_scopes,
                allow_module_locals_mapping=allow_module_locals_mapping,
                allow_local_namespace_mapping=allow_local_namespace_mapping,
            )
            return _static_sequence_aliases_from_resolved_items(
                tuple(_resolve_static_member_names(target_roots, field, alias_scopes) for field in fields)
            )

    item_field_groups = _operator_accessor_field_groups(accessor_names, _OPERATOR_ITEMGETTER_ALIAS_PREFIX)
    if len(item_field_groups) == 1:
        fields = next(iter(item_field_groups))
        decoded_keys = tuple(_decode_operator_itemgetter_key(field) for field in fields)
        if len(fields) > 1 and all(resolved for resolved, _key in decoded_keys):
            return _static_sequence_aliases_from_resolved_items(
                tuple(
                    _resolve_operator_itemgetter_target_names(
                        target_node,
                        key,
                        alias_scopes,
                        allow_module_locals_mapping=allow_module_locals_mapping,
                        allow_local_namespace_mapping=allow_local_namespace_mapping,
                    )
                    for _resolved, key in decoded_keys
                )
            )
    return None


def _resolve_operator_methodcaller_dynamic_access_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    if not isinstance(node, ast.Call):
        return None
    target_node = _operator_accessor_target_node(node)
    if target_node is None:
        return None
    method_fields = _operator_methodcaller_fields(
        _resolve_static_reference_names(
            node.func,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
    )
    if not method_fields:
        return None

    target_roots: frozenset[str] | None = None
    mapping_roots: frozenset[str] | None = None
    resolved_names: set[str] = set()
    for method_name, lookup_field, fallback_name in method_fields:
        lookup_resolved, lookup_key = _decode_operator_itemgetter_key(lookup_field)
        if not lookup_resolved:
            continue
        if method_name == "__getattribute__":
            if not isinstance(lookup_key, str):
                continue
            if target_roots is None:
                target_roots = _resolve_static_reference_names(
                    target_node,
                    alias_scopes,
                    allow_module_locals_mapping=allow_module_locals_mapping,
                    allow_local_namespace_mapping=allow_local_namespace_mapping,
                )
            resolved_names.update(_resolve_static_member_names(target_roots, lookup_key, alias_scopes) or frozenset())
            continue
        if method_name in _NAMESPACE_LOOKUP_METHODS:
            literal_lookup = _resolve_static_container_item_names(
                target_node,
                lookup_key,
                alias_scopes,
                allow_module_locals_mapping=allow_module_locals_mapping,
                allow_local_namespace_mapping=allow_local_namespace_mapping,
            )
            if literal_lookup is not None:
                selected_names, selected_value_guaranteed = literal_lookup
                resolved_names.update(selected_names or frozenset())
                if fallback_name and not selected_value_guaranteed:
                    resolved_names.update(_apply_aliases(fallback_name, alias_scopes) or frozenset())
                continue
            if mapping_roots is None:
                mapping_roots = _resolve_namespace_mapping_roots(
                    target_node,
                    alias_scopes,
                    allow_module_locals_mapping=allow_module_locals_mapping,
                    allow_local_namespace_mapping=allow_local_namespace_mapping,
                )
            if isinstance(lookup_key, str):
                selected_value_guaranteed = bool(mapping_roots)
                for mapping_root in mapping_roots or frozenset():
                    selected_names, guaranteed = _resolve_mapping_root_item_names(
                        mapping_root,
                        lookup_key,
                        alias_scopes,
                        allow_module_locals_mapping=allow_module_locals_mapping,
                    )
                    resolved_names.update(selected_names or frozenset())
                    selected_value_guaranteed = selected_value_guaranteed and guaranteed
            else:
                selected_value_guaranteed = False
            if fallback_name and not selected_value_guaranteed:
                resolved_names.update(_apply_aliases(fallback_name, alias_scopes) or frozenset())
    return frozenset(resolved_names) or None


def _resolve_operator_methodcaller_invoked_method_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    if not isinstance(node, ast.Call):
        return None
    target_node = _operator_accessor_target_node(node)
    if target_node is None:
        return None
    method_names = frozenset(
        method_name
        for method_name, _lookup_name, _fallback_name in _operator_methodcaller_fields(
            _resolve_static_reference_names(
                node.func,
                alias_scopes,
                allow_module_locals_mapping=allow_module_locals_mapping,
                allow_local_namespace_mapping=allow_local_namespace_mapping,
            )
        )
        if method_name not in _OPERATOR_METHODCALLER_DYNAMIC_ACCESS_METHODS and "." not in method_name
    )
    if not method_names:
        return None
    target_roots = _resolve_static_reference_names(
        target_node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    resolved_names: set[str] = set()
    for method_name in method_names:
        resolved_names.update(_resolve_static_member_names(target_roots, method_name, alias_scopes) or frozenset())
    return frozenset(resolved_names) or None


def _resolve_ctypes_library_loader_instance_roots(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    if isinstance(node, ast.Subscript):
        library_name = _resolve_static_string(node.slice)
        if library_name is None:
            return None
        resolved_loader_names = _resolve_static_reference_names(
            node.value,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        if resolved_loader_names is None:
            return None
        subscript_loader_roots = frozenset(
            resolved_name
            for resolved_name in resolved_loader_names
            if _is_ctypes_library_loader_object_root(resolved_name)
        )
        return frozenset(f"{loader_root}.{library_name}" for loader_root in subscript_loader_roots) or None

    if not isinstance(node, ast.Call):
        return None

    resolved_func_names = _resolve_static_reference_names(
        node.func,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if resolved_func_names is None:
        return None

    loader_roots: set[str] = set()
    constructor_roots = resolved_func_names & _CTYPES_LIBRARY_LOADER_CONSTRUCTORS
    if constructor_roots:
        loader_type_node = _single_static_call_argument(node.args, node.keywords, keyword_name="dlltype")
        if loader_type_node is not None:
            resolved_loader_types = _resolve_static_reference_names(
                loader_type_node,
                alias_scopes,
                allow_module_locals_mapping=allow_module_locals_mapping,
                allow_local_namespace_mapping=allow_local_namespace_mapping,
            )
            if _canonical_ctypes_loader_type_aliases(resolved_loader_types):
                loader_roots.add(_CTYPES_LIBRARY_LOADER_INSTANCE_ROOT)
    library_name_node = _single_static_call_argument(node.args, node.keywords, keyword_name="name")
    if library_name_node is not None and not _is_static_non_string(library_name_node):
        library_name = _resolve_static_string(library_name_node)
        for resolved_func_name in resolved_func_names:
            split_reference = _split_ctypes_loader_reference(resolved_func_name)
            if split_reference is None:
                continue
            root_name, suffix = split_reference
            if suffix in {"__getitem__", "__getattr__", "LoadLibrary"}:
                loader_roots.add(f"{root_name}.{library_name or _CTYPES_DYNAMIC_LIBRARY_NAME}")
    for resolved_func_name in resolved_func_names:
        stripped_func_name = _strip_dunder_call_suffixes(resolved_func_name)
        root_name, separator, method_name = stripped_func_name.rpartition(".")
        if not separator or root_name not in _CTYPES_LIBRARY_LOADER_CONSTRUCTORS:
            continue
        if method_name not in {"__getitem__", "__getattr__", "LoadLibrary"}:
            continue
        self_node: ast.AST | None = None
        unbound_library_name_node: ast.AST | None = None
        expanded_args = _expanded_static_call_args(node)
        keyword_values = _static_call_keyword_arguments(node.keywords, frozenset({"self", "name"}))
        if expanded_args is None or keyword_values is None or len(expanded_args) > 2:
            continue
        if len(expanded_args) >= 1:
            self_node = expanded_args[0]
        if len(expanded_args) >= 2:
            unbound_library_name_node = expanded_args[1]
        if "self" in keyword_values:
            if self_node is not None:
                continue
            self_node = keyword_values["self"]
        if "name" in keyword_values:
            if unbound_library_name_node is not None:
                continue
            unbound_library_name_node = keyword_values["name"]
        if self_node is None or unbound_library_name_node is None or _is_static_non_string(unbound_library_name_node):
            continue
        resolved_self_names = _resolve_static_reference_names(
            self_node,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        self_loader_roots = frozenset(
            resolved_name
            for resolved_name in resolved_self_names or frozenset()
            if _is_ctypes_library_loader_object_root(resolved_name)
        )
        library_name = _resolve_static_string(unbound_library_name_node)
        loader_roots.update(
            f"{loader_root}.{library_name or _CTYPES_DYNAMIC_LIBRARY_NAME}" for loader_root in self_loader_roots
        )
    return frozenset(loader_roots) or None


def _union_static_reference_names(
    nodes: Iterable[ast.AST],
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    """Resolve each candidate value and union the known references.

    Used for expressions that evaluate to one of several operands at runtime
    (``a if c else b``, ``a or b``); a member load on the result is risky when
    *any* operand resolves to a loader/controller.
    """
    combined: set[str] = set()
    for sub_node in nodes:
        resolved = _resolve_static_reference_names(
            sub_node,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        if resolved:
            combined.update(resolved)
    return frozenset(combined) or None


def _statically_known_truth_value(node: ast.AST, alias_scopes: _AliasScopes) -> bool | None:
    if isinstance(node, ast.Constant):
        if node.value is None:
            return False
        if isinstance(node.value, (bool, int, float, complex, str, bytes)):
            return bool(node.value)
        return None
    call_name = _resolve_call_name(node)
    if call_name is None:
        return None
    implicit_builtin_name = f"builtins.{call_name}" if call_name in {"print", "len"} else None
    if implicit_builtin_name is not None and not _lookup_bound_alias(call_name, alias_scopes)[1]:
        resolved_names = _apply_aliases(implicit_builtin_name, alias_scopes)
    else:
        resolved_names = _apply_aliases(call_name, alias_scopes)
    known_truthy_names = _STATIC_OVERWRITABLE_HIGH_RISK_REFERENCES | _STATIC_TRUTHY_BUILTIN_REFERENCES
    return True if resolved_names and resolved_names <= known_truthy_names else None


def _resolve_sys_modules_lookup_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    if not isinstance(node, ast.Subscript):
        return None
    module_name = _resolve_static_string(node.slice)
    if module_name not in _TRACKED_STATIC_MODULE_ROOTS:
        return None
    registry_names = _resolve_static_reference_names(
        node.value,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if registry_names != frozenset({"sys.modules"}):
        return None
    selected_names, found = _lookup_bound_alias(f"{_SYS_MODULES_BINDING_PREFIX}{module_name}", alias_scopes)
    return selected_names if found else frozenset({module_name})


def _resolve_static_reference_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
    if isinstance(node, ast.NamedExpr):
        return _resolve_static_reference_names(
            node.value,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
    if isinstance(node, ast.IfExp):
        condition_value = _statically_known_truth_value(node.test, alias_scopes)
        if condition_value is not None:
            return _resolve_static_reference_names(
                node.body if condition_value else node.orelse,
                alias_scopes,
                allow_module_locals_mapping=allow_module_locals_mapping,
                allow_local_namespace_mapping=allow_local_namespace_mapping,
            )
        return _union_static_reference_names(
            (node.body, node.orelse),
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
    if isinstance(node, ast.BoolOp):
        for value in node.values[:-1]:
            truth_value = _statically_known_truth_value(value, alias_scopes)
            if truth_value is None:
                break
            if isinstance(node.op, ast.Or) and truth_value:
                return _resolve_static_reference_names(
                    value,
                    alias_scopes,
                    allow_module_locals_mapping=allow_module_locals_mapping,
                    allow_local_namespace_mapping=allow_local_namespace_mapping,
                )
            if isinstance(node.op, ast.And) and not truth_value:
                return _resolve_static_reference_names(
                    value,
                    alias_scopes,
                    allow_module_locals_mapping=allow_module_locals_mapping,
                    allow_local_namespace_mapping=allow_local_namespace_mapping,
                )
        else:
            return _resolve_static_reference_names(
                node.values[-1],
                alias_scopes,
                allow_module_locals_mapping=allow_module_locals_mapping,
                allow_local_namespace_mapping=allow_local_namespace_mapping,
            )
        return _union_static_reference_names(
            node.values,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
    sys_modules_names = _resolve_sys_modules_lookup_names(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if sys_modules_names is not None:
        return sys_modules_names
    operator_accessor_factory_names = _resolve_operator_accessor_factory_names(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if operator_accessor_factory_names is not None:
        return operator_accessor_factory_names
    operator_attrgetter_names = _resolve_operator_attrgetter_call_result_names(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if operator_attrgetter_names is not None:
        return operator_attrgetter_names
    operator_itemgetter_names = _resolve_operator_itemgetter_call_result_names(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if operator_itemgetter_names is not None:
        return operator_itemgetter_names
    operator_methodcaller_access_names = _resolve_operator_methodcaller_dynamic_access_names(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if operator_methodcaller_access_names is not None:
        return operator_methodcaller_access_names
    operator_accessor_sequence_item_names = _resolve_operator_accessor_sequence_item_names(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if operator_accessor_sequence_item_names is not None:
        return operator_accessor_sequence_item_names
    if isinstance(node, ast.Attribute) and node.attr == "__call__":
        callable_names = _resolve_static_reference_names(
            node.value,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        if callable_names is not None and any(
            name.endswith(f".__dict__.{method}") for name in callable_names for method in _NAMESPACE_MAPPING_METHODS
        ):
            return frozenset(f"{name}.__call__" for name in callable_names)
        if callable_names is not None:
            return frozenset(f"{name}.__call__" for name in callable_names)
    if isinstance(node, ast.Attribute) and node.attr in _NAMESPACE_MAPPING_METHODS:
        mapping_method_roots = _resolve_namespace_mapping_roots(
            node.value,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        if mapping_method_roots is not None:
            return frozenset(f"{root}.__dict__.{node.attr}" for root in mapping_method_roots)
    ctypes_loader_roots = _resolve_ctypes_library_loader_instance_roots(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if ctypes_loader_roots is not None:
        return ctypes_loader_roots
    if isinstance(node, ast.Call):
        webbrowser_controller_roots = _resolve_webbrowser_controller_factory_roots(
            node,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        if webbrowser_controller_roots is not None:
            return webbrowser_controller_roots
    call_name = _resolve_call_name(node)
    if call_name is not None:
        resolved_names = _apply_aliases(call_name, alias_scopes)
        if call_name == "__builtins__" and resolved_names == frozenset({"__builtins__"}):
            return frozenset({"builtins", "builtins.__dict__"})
        return _normalize_implicit_builtins_names(resolved_names, alias_scopes)
    getattr_names = _resolve_getattr_call_names(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if getattr_names is not None:
        return _normalize_implicit_builtins_names(getattr_names, alias_scopes)
    if isinstance(node, ast.Attribute) and node.attr != "__call__":
        ctypes_loader_roots = _resolve_ctypes_library_loader_instance_roots(
            node.value,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        if ctypes_loader_roots is not None:
            return _apply_aliases_to_names(
                frozenset(f"{root}.{node.attr}" for root in ctypes_loader_roots), alias_scopes
            )
        webbrowser_controller_roots = _resolve_webbrowser_controller_factory_roots(
            node.value,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        if webbrowser_controller_roots is not None:
            return frozenset(f"{root}.{node.attr}" for root in webbrowser_controller_roots)
        resolved_value_names = _resolve_static_reference_names(
            node.value,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        if resolved_value_names is not None:
            return frozenset(f"{name}.{node.attr}" for name in resolved_value_names)
        selected_names = _resolve_namespace_mapping_lookup_names(
            node.value,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        if selected_names is not None:
            return frozenset(f"{name}.{node.attr}" for name in selected_names)
        attribute_roots = _resolve_namespace_mapping_roots(
            node.value,
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        if attribute_roots is not None:
            return frozenset(f"{root}.{node.attr}" for root in attribute_roots)
    mapping_lookup_names = _resolve_namespace_mapping_lookup_names(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if mapping_lookup_names is not None:
        return mapping_lookup_names
    if isinstance(node, ast.Subscript):
        key_resolved, key = _resolve_static_item_key(node.slice)
        if key_resolved:
            static_item = _resolve_static_container_item_names(
                node.value,
                key,
                alias_scopes,
                allow_module_locals_mapping=allow_module_locals_mapping,
                allow_local_namespace_mapping=allow_local_namespace_mapping,
            )
            if static_item is not None:
                return static_item[0]
    mapping_roots = _resolve_namespace_mapping_roots(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if mapping_roots is not None:
        return frozenset(name for root in mapping_roots for name in (root, f"{root}.__dict__"))
    globals_mapping_alias = _resolve_globals_mapping_alias(
        node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if globals_mapping_alias is not None:
        return globals_mapping_alias
    return None


def _is_high_risk_python_call_name(name: str) -> bool:
    return _normalized_high_risk_python_call_name(name) is not None


def _wildcard_import_aliases(module: str) -> Iterator[tuple[str, str]]:
    prefix = f"{module}."
    call_names = set(_HIGH_RISK_PYTHON_CALLS)
    if module == "webbrowser":
        call_names.update(_WEBBROWSER_CONTROLLER_FACTORIES)
    if module == "ctypes":
        call_names.update(_CTYPES_LIBRARY_LOADER_OBJECTS | _CTYPES_LIBRARY_LOADER_CONSTRUCTORS)
    if module == "operator":
        call_names.update(_STATIC_OPERATOR_ACCESSOR_HELPER_REFERENCES)
    for call_name in sorted(call_names):
        if not call_name.startswith(prefix):
            continue
        exported_name = call_name.removeprefix(prefix).split(".", maxsplit=1)[0]
        if exported_name.startswith("_"):
            continue
        if module == "asyncio" and exported_name == "subprocess":
            continue
        yield exported_name, f"{module}.{exported_name}"


def _binding_names(target: ast.AST) -> Iterator[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, ast.Starred):
        yield from _binding_names(target.value)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _binding_names(element)


class _HighRiskPythonCallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.alias_scopes: _AliasScopes = [{}]
        self._member_binding_roots: set[str] = set()
        self._class_scope_ids: set[int] = set()
        self._comprehension_outer_scope_indices: list[int] = []
        self._comprehension_unknown_side_effects: list[bool] = []
        self._eager_comprehension_depth = 0
        self._deferred_execution_depth = 0
        self._call_result_aliases: dict[int, _AliasValue] = {}
        self._known_class_names: set[str] = set()
        self._classes_with_local_initializers: set[str] = set()
        self._classes_with_forwarding_initializers: set[str] = set()
        self._class_identity_aliases: dict[str, frozenset[str]] = {}
        self._instance_binding_generations: dict[str, int] = {}
        self._static_container_generation = 0
        self._non_module_scope_depth = 0
        self._annotations_are_postponed = False
        self.risky_calls: set[str] = set()

    def visit_Module(self, node: ast.Module) -> None:
        annotations_are_postponed = self._annotations_are_postponed
        self._annotations_are_postponed = any(
            isinstance(statement, ast.ImportFrom)
            and statement.module == "__future__"
            and any(alias.name == "annotations" for alias in statement.names)
            for statement in node.body
        )
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self._annotations_are_postponed = annotations_are_postponed

    def _resolve_reference_names(self, node: ast.AST) -> frozenset[str] | None:
        resolved_names = _resolve_static_reference_names(
            node,
            self.alias_scopes,
            allow_module_locals_mapping=self._non_module_scope_depth == 0,
            allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
        )
        noncanonical_namespace_roots = self._noncanonical_module_namespace_roots(node)
        if noncanonical_namespace_roots:
            resolved_names = self._merge_alias_values(
                resolved_names, frozenset(f"{root}.__dict__" for root in noncanonical_namespace_roots)
            )
        if isinstance(node, ast.Attribute):
            owner_names = _resolve_static_reference_names(
                node.value,
                self.alias_scopes,
                allow_module_locals_mapping=self._non_module_scope_depth == 0,
                allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
            )
            module_roots = frozenset(
                owner_name for owner_name in owner_names or frozenset() if owner_name in _TRACKED_STATIC_MODULE_ROOTS
            )
            uncertain_names = frozenset(
                f"{module_root}.{node.attr}"
                for module_root in module_roots
                if _is_overwritable_high_risk_reference(f"{module_root}.{node.attr}")
            )
            if uncertain_names and not self._module_attribute_helper_has_canonical_dispatch(module_roots):
                return self._merge_alias_values(resolved_names, uncertain_names)
        uncertain_namespace_names = self._noncanonical_namespace_lookup_names(node)
        if uncertain_namespace_names:
            return self._merge_alias_values(resolved_names, uncertain_namespace_names)
        return resolved_names

    def _noncanonical_module_namespace_roots(self, node: ast.AST) -> frozenset[str]:
        module_node: ast.AST | None = None
        if isinstance(node, ast.Attribute) and node.attr == "__dict__":
            module_node = node.value
        elif isinstance(node, ast.Call):
            helper_names = _resolve_static_reference_names(
                node.func,
                self.alias_scopes,
                allow_module_locals_mapping=self._non_module_scope_depth == 0,
                allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
            )
            if (
                helper_names and helper_names <= {"vars", "builtins.vars"} and len(node.args) == 1 and not node.keywords
            ) or (
                helper_names
                and helper_names <= {"getattr", "builtins.getattr"}
                and len(node.args) >= 2
                and _resolve_static_string(node.args[1]) == "__dict__"
            ):
                module_node = node.args[0]
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "__getattribute__"
                and len(node.args) == 1
                and not node.keywords
                and _resolve_static_string(node.args[0]) == "__dict__"
            ):
                module_node = node.func.value
        if module_node is None:
            return frozenset()
        resolved_module_names = _resolve_static_reference_names(
            module_node,
            self.alias_scopes,
            allow_module_locals_mapping=self._non_module_scope_depth == 0,
            allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
        )
        module_roots = frozenset(
            name for name in resolved_module_names or frozenset() if name in _TRACKED_STATIC_MODULE_ROOTS
        )
        if module_roots and not self._module_attribute_helper_has_canonical_dispatch(module_roots):
            return module_roots
        return frozenset()

    def _noncanonical_namespace_lookup_names(self, node: ast.AST) -> frozenset[str]:
        mapping_node: ast.AST | None = None
        key_node: ast.AST | None = None
        if isinstance(node, ast.Subscript):
            mapping_node = node.value
            key_node = node.slice
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args:
            if node.func.attr not in _NAMESPACE_LOOKUP_METHODS:
                return frozenset()
            descriptor_names = _resolve_static_reference_names(
                node.func,
                self.alias_scopes,
                allow_module_locals_mapping=self._non_module_scope_depth == 0,
                allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
            )
            is_descriptor = bool(descriptor_names and descriptor_names & _NAMESPACE_LOOKUP_DESCRIPTORS)
            mapping_node = node.args[0] if is_descriptor else node.func.value
            key_node = node.args[1] if is_descriptor and len(node.args) > 1 else node.args[0]
        if mapping_node is None or key_node is None:
            return frozenset()
        member_name = _resolve_static_string(key_node)
        if member_name is None:
            return frozenset()
        return frozenset(
            f"{root}.{member_name}"
            for root in self._noncanonical_module_namespace_roots(mapping_node)
            if _is_overwritable_high_risk_reference(f"{root}.{member_name}")
        )

    def _bind_imported_static_members(
        self,
        local_name: str,
        import_name: str,
        *,
        preserve_existing: bool,
        reset_to_canonical: bool = False,
    ) -> None:
        prefix = f"{import_name}."
        for reference in _TRACKED_STATIC_MEMBER_REFERENCES:
            if not reference.startswith(prefix):
                continue
            local_reference = f"{local_name}{reference.removeprefix(import_name)}"
            if preserve_existing and local_reference in self.alias_scopes[-1]:
                continue
            if reset_to_canonical:
                self.alias_scopes[-1][local_reference] = frozenset({reference})
                self._record_member_binding_name(local_reference)
                continue
            canonical_name = f"{_STATIC_CANONICAL_MEMBER_PREFIX}{reference}"
            canonical_binding, found = _lookup_bound_alias(canonical_name, self.alias_scopes)
            self.alias_scopes[-1][local_reference] = canonical_binding if found else frozenset({reference})
            self._record_member_binding_name(local_reference)

    def _record_member_binding_name(self, name: str) -> None:
        if "." in name:
            self._member_binding_roots.add(name.split(".", maxsplit=1)[0])

    def _shadow_member_bindings(self, scope_index: int, local_name: str) -> None:
        if "." in local_name or local_name.startswith(_MODULE_NAMESPACE_WRITE_PREFIX):
            return
        if local_name not in self._member_binding_roots:
            return
        prefix = f"{local_name}."
        current_scope = self.alias_scopes[scope_index]
        for scope in self.alias_scopes:
            for name in tuple(scope):
                if name.startswith(prefix):
                    current_scope[name] = None

    def _record_import(self, alias: ast.alias, import_name: str) -> None:
        local_name = alias.asname or alias.name
        registry_binding, registry_found = _lookup_bound_alias(
            f"{_SYS_MODULES_BINDING_PREFIX}{import_name}", self.alias_scopes
        )
        module_name, separator, member_name = import_name.partition(".")
        module_registry_binding, module_registry_found = (
            _lookup_bound_alias(f"{_SYS_MODULES_BINDING_PREFIX}{module_name}", self.alias_scopes)
            if separator
            else (None, False)
        )
        known_module_registry_replacement = isinstance(
            module_registry_binding, frozenset
        ) and module_registry_binding != frozenset({module_name})
        if known_module_registry_replacement:
            assert isinstance(module_registry_binding, frozenset)
            self._bind_name(local_name, frozenset(f"{module}.{member_name}" for module in module_registry_binding))
            return
        if module_registry_found and module_registry_binding is None:
            self._bind_name(local_name, None)
            return
        known_registry_replacement = isinstance(registry_binding, frozenset) and registry_binding != frozenset(
            {import_name}
        )
        reset_to_canonical = (
            registry_found and not known_registry_replacement and registry_binding != frozenset({import_name})
        )
        previous_names, _found = _lookup_bound_alias(local_name, self.alias_scopes)
        preserve_existing = (
            not reset_to_canonical and isinstance(previous_names, frozenset) and import_name in previous_names
        )
        imported_binding: _AliasValue = registry_binding if known_registry_replacement else frozenset({import_name})
        if import_name in _TRACKED_STATIC_MEMBER_REFERENCES:
            current_binding, found = _lookup_bound_alias(
                f"{_STATIC_CANONICAL_MEMBER_PREFIX}{import_name}", self.alias_scopes
            )
            if found:
                imported_binding = current_binding
        self._bind_name(local_name, imported_binding)
        if known_registry_replacement:
            return
        self._bind_imported_static_members(
            local_name,
            import_name,
            preserve_existing=preserve_existing,
            reset_to_canonical=reset_to_canonical,
        )

    def _bind_name(self, name: str, resolved_names: _AliasValue) -> None:
        previous_names, _found = _lookup_bound_alias(name, self.alias_scopes)
        preserves_module_binding = (
            isinstance(previous_names, frozenset)
            and isinstance(resolved_names, frozenset)
            and bool(previous_names & resolved_names)
        )
        if not preserves_module_binding:
            self._shadow_member_bindings(-1, name)
        self.alias_scopes[-1][name] = resolved_names
        self._record_member_binding_name(name)

    def _bind_name_in_scope(self, scope_index: int, name: str, resolved_names: _AliasValue) -> None:
        previous_names, _found = _lookup_bound_alias(name, self.alias_scopes[: scope_index + 1])
        preserves_module_binding = (
            isinstance(previous_names, frozenset)
            and isinstance(resolved_names, frozenset)
            and bool(previous_names & resolved_names)
        )
        if not preserves_module_binding:
            self._shadow_member_bindings(scope_index, name)
        self.alias_scopes[scope_index][name] = resolved_names
        self._record_member_binding_name(name)

    def _should_track_syntactic_static_reference(self, syntactic_name: str) -> bool:
        root_name = syntactic_name.split(".", maxsplit=1)[0]
        root_aliases, found = _lookup_bound_alias(root_name, self.alias_scopes)
        return not found or (isinstance(root_aliases, frozenset) and root_name in root_aliases)

    def _localize_instance_binding_value(
        self, local_name: str, value: ast.AST | None, resolved_names: _AliasValue
    ) -> _AliasValue:
        if not isinstance(resolved_names, frozenset):
            return resolved_names
        localized_names = set(resolved_names)
        if _STATIC_INERT_CTYPES_LIBRARY_LOADER in localized_names:
            localized_names.remove(_STATIC_INERT_CTYPES_LIBRARY_LOADER)
            localized_names.add(
                self._localized_instance_root_for_binding(_STATIC_INERT_CTYPES_LIBRARY_LOADER, local_name)
            )
        if _CTYPES_LIBRARY_LOADER_INSTANCE_ROOT in localized_names:
            localized_names.remove(_CTYPES_LIBRARY_LOADER_INSTANCE_ROOT)
            localized_names.add(
                self._localized_instance_root_for_binding(_CTYPES_LIBRARY_LOADER_INSTANCE_ROOT, local_name)
            )
        webbrowser_controller_roots = (
            _resolve_webbrowser_controller_factory_roots(
                value,
                self.alias_scopes,
                allow_module_locals_mapping=self._non_module_scope_depth == 0,
                allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
            )
            if value is not None
            else None
        )
        for controller_root in webbrowser_controller_roots or frozenset():
            if controller_root in localized_names:
                localized_names.remove(controller_root)
                localized_names.add(self._localized_instance_root_for_binding(controller_root, local_name))
        return frozenset(localized_names)

    def _localized_instance_root_for_binding(self, root_name: str, local_name: str) -> str:
        generation = self._instance_binding_generations.get(local_name, 0) + 1
        self._instance_binding_generations[local_name] = generation
        return _localized_instance_root(root_name, f"{local_name}#{generation}")

    def _has_tracked_local_static_member_binding(self, syntactic_name: str | None) -> bool:
        if syntactic_name is None or "." not in syntactic_name:
            return False
        _member_aliases, has_member_binding = _lookup_bound_alias(syntactic_name, self.alias_scopes)
        if not has_member_binding:
            return False
        root_name, member_suffix = syntactic_name.split(".", maxsplit=1)
        root_aliases, _found = _lookup_bound_alias(root_name, self.alias_scopes)
        return isinstance(root_aliases, frozenset) and any(
            f"{root_alias}.{member_suffix}" in _STATIC_OVERWRITABLE_HIGH_RISK_REFERENCES for root_alias in root_aliases
        )

    def _bind_local_static_member_aliases(
        self,
        reference_name: str,
        resolved_names: _AliasValue,
        *,
        eager_scope_index: int | None = None,
    ) -> None:
        local_names: set[tuple[int, str]] = set()
        for scope_index, scope in enumerate(self.alias_scopes):
            for local_name in tuple(scope):
                if "." not in local_name:
                    continue
                root_name, member_suffix = local_name.split(".", maxsplit=1)
                root_aliases, _found = _lookup_bound_alias(root_name, self.alias_scopes[: scope_index + 1])
                if not isinstance(root_aliases, frozenset):
                    continue
                if any(f"{root_alias}.{member_suffix}" == reference_name for root_alias in root_aliases):
                    local_names.add((scope_index, local_name))
        for scope_index, local_name in local_names:
            if eager_scope_index is None:
                self._bind_name(local_name, resolved_names)
            elif scope_index <= eager_scope_index:
                self._bind_name_in_scope(scope_index, local_name, resolved_names)

    def _bind_member_reference(self, reference_name: str, resolved_names: _AliasValue) -> None:
        eager_scope_index = (
            self._comprehension_outer_scope_indices[-1]
            if self._eager_comprehension_depth and self._comprehension_outer_scope_indices
            else None
        )

        def bind_name(name: str, value: _AliasValue) -> None:
            if eager_scope_index is not None:
                self._bind_name_in_scope(eager_scope_index, name, value)
            else:
                self._bind_name(name, value)

        if reference_name in _TRACKED_STATIC_MEMBER_REFERENCES:
            bind_name(f"{_STATIC_CANONICAL_MEMBER_PREFIX}{reference_name}", resolved_names)
        bind_name(reference_name, resolved_names)
        if reference_name in _STATIC_OVERWRITABLE_HIGH_RISK_REFERENCES:
            self._bind_local_static_member_aliases(
                reference_name,
                resolved_names,
                eager_scope_index=eager_scope_index,
            )

    @staticmethod
    def _generator_direct_body_is_guaranteed(node: ast.GeneratorExp) -> bool:
        if not isinstance(node.elt, ast.Call):
            return False
        for generator in node.generators:
            if generator.is_async or generator.ifs:
                return False
            if isinstance(generator.iter, (ast.List, ast.Tuple, ast.Set)):
                if not generator.iter.elts:
                    return False
            elif isinstance(generator.iter, ast.Dict):
                if not generator.iter.keys:
                    return False
            else:
                return False
        return True

    def _bind_module_namespace_key(self, key: str, resolved_names: _AliasValue) -> None:
        self._bind_name(f"{_MODULE_NAMESPACE_WRITE_PREFIX}{key}", resolved_names)
        if self._non_module_scope_depth == 0:
            self._bind_name(key, resolved_names)

    def _delete_alias_binding(self, name: str) -> None:
        module_write_name = f"{_MODULE_NAMESPACE_WRITE_PREFIX}{name}"
        for scope in self.alias_scopes:
            scope.pop(name, None)
            scope.pop(module_write_name, None)

    def _restore_deleted_dynamic_target_bindings(
        self, target_names: frozenset[str] | set[str], syntactic_name: str | None
    ) -> bool:
        dynamic_target_names = frozenset(
            target_name
            for target_name in target_names
            if _is_dynamic_overwritable_high_risk_reference(target_name)
            and any(target_name in scope for scope in self.alias_scopes)
        )
        if not dynamic_target_names:
            return False
        current_scope = self.alias_scopes[-1]
        for target_name in dynamic_target_names:
            current_scope[target_name] = frozenset({target_name})
            self._record_member_binding_name(target_name)
        if syntactic_name is not None:
            current_scope[syntactic_name] = dynamic_target_names
            self._record_member_binding_name(syntactic_name)
        return True

    def _resolve_binding_value_names(self, value: ast.AST | None) -> _AliasValue:
        if value is None:
            return None
        static_container_aliases = _resolve_static_container_aliases(
            value,
            self.alias_scopes,
            allow_module_locals_mapping=self._non_module_scope_depth == 0,
            allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
        )
        if static_container_aliases is not None:
            self._static_container_generation += 1
            aliases = {
                *static_container_aliases,
                f"{_STATIC_CONTAINER_ID_ALIAS_PREFIX}{self._static_container_generation}",
            }
            if isinstance(value, ast.List):
                aliases.add(_STATIC_MUTABLE_SEQUENCE_ALIAS)
            return frozenset(aliases)
        operator_accessor_sequence_aliases = _resolve_operator_accessor_result_sequence_aliases(
            value,
            self.alias_scopes,
            allow_module_locals_mapping=self._non_module_scope_depth == 0,
            allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
        )
        if operator_accessor_sequence_aliases is not None:
            self._static_container_generation += 1
            return frozenset(
                {
                    *operator_accessor_sequence_aliases,
                    f"{_STATIC_CONTAINER_ID_ALIAS_PREFIX}{self._static_container_generation}",
                }
            )
        inert_call_result = self._statically_inert_call_result_names(value)
        if inert_call_result is not None:
            return inert_call_result
        if isinstance(value, ast.Call) and id(value) in self._call_result_aliases:
            return self._call_result_aliases[id(value)]
        value_name = _resolve_call_name(value)
        if value_name is not None and _is_high_risk_python_call_name(value_name):
            return frozenset({value_name})
        return self._resolve_reference_names(value)

    def _statically_inert_call_result_names(self, value: ast.AST) -> frozenset[str] | None:
        if not self._is_statically_inert_loader_construction(
            value
        ) or not self._statically_inert_loader_dispatch_is_canonical(
            _STATIC_CTYPES_LIBRARY_LOADER_CONSTRUCTION_DISPATCH_REFERENCES
        ):
            return None
        return frozenset({_STATIC_INERT_CTYPES_LIBRARY_LOADER})

    def _is_statically_inert_loader_construction(self, value: ast.AST) -> bool:
        if not isinstance(value, ast.Call) or self._resolve_reference_names(value.func) != frozenset(
            {"ctypes.LibraryLoader"}
        ):
            return False
        loader_type_node = _single_static_call_argument(value.args, value.keywords, keyword_name="dlltype")
        return loader_type_node is not None and self._resolve_reference_names(loader_type_node) in {
            frozenset({"len"}),
            frozenset({"builtins.len"}),
        }

    def _restore_reassigned_instance_member_defaults(self, target_name: str, resolved_names: _AliasValue) -> None:
        if not isinstance(resolved_names, frozenset):
            return
        instance_roots = frozenset(name for name in resolved_names if _is_tracked_dynamic_instance_root(name))
        if not instance_roots:
            return

        current_scope = self.alias_scopes[-1]
        for instance_root in instance_roots:
            instance_prefix = f"{instance_root}."
            for scope in self.alias_scopes:
                for name in tuple(scope):
                    if name.startswith(instance_prefix):
                        current_scope[name] = frozenset({name})

        syntactic_prefix = f"{target_name}."
        for scope in self.alias_scopes:
            for name in tuple(scope):
                if name.startswith(syntactic_prefix):
                    suffix = name[len(syntactic_prefix) :]
                    current_scope[name] = frozenset(f"{instance_root}.{suffix}" for instance_root in instance_roots)

    def _push_alias_scope(self, scope: _AliasScope | None = None) -> None:
        new_scope = scope if scope is not None else {}
        self.alias_scopes.append(new_scope)
        for name in new_scope:
            self._record_member_binding_name(name)

    def _pop_alias_scope(self) -> None:
        self.alias_scopes.pop()

    def _sys_modules_target_name(self, target: ast.AST) -> str | None:
        if not isinstance(target, ast.Subscript):
            return None
        module_name = _resolve_static_string(target.slice)
        if module_name not in _TRACKED_STATIC_MODULE_ROOTS:
            return None
        if self._resolve_reference_names(target.value) != frozenset({"sys.modules"}):
            return None
        return f"{_SYS_MODULES_BINDING_PREFIX}{module_name}"

    def _bind_target_to_value(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            resolved_names = self._resolve_binding_value_names(value)
            localized_names = self._localize_instance_binding_value(target.id, value, resolved_names)
            self._bind_name(target.id, localized_names)
            self._restore_reassigned_instance_member_defaults(target.id, localized_names)
            if self._non_module_scope_depth == 0:
                class_identity_names = self._resolve_class_identity_names(value)
                if class_identity_names:
                    self._class_identity_aliases[target.id] = class_identity_names
                else:
                    self._class_identity_aliases.pop(target.id, None)
        elif isinstance(target, ast.Subscript):
            registry_target_name = self._sys_modules_target_name(target)
            if registry_target_name is not None:
                self._bind_name(registry_target_name, self._resolve_binding_value_names(value))
                return
            key = _resolve_static_string(target.slice)
            roots = _resolve_namespace_mapping_roots(
                target.value,
                self.alias_scopes,
                allow_module_locals_mapping=self._non_module_scope_depth == 0,
                allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
            )
            if key is not None and roots is not None:
                if self._namespace_mapping_dispatch_is_uncertain(roots):
                    self._invalidate_unknown_callable_side_effects()
                    return
                resolved_value = self._resolve_binding_value_names(value)
                roots = self._promote_mutated_statically_inert_loader_roots(roots, key, value, resolved_value)
                localized_value = self._localize_instance_binding_value(key, value, resolved_value)
                for root in roots:
                    if root in _TRACKED_MODULE_NAMESPACE_ALIASES:
                        self._bind_module_namespace_key(key, localized_value)
                        self._restore_reassigned_instance_member_defaults(key, localized_value)
                        continue
                    if root == _LOCAL_NAMESPACE_MAPPING_ALIAS:
                        self._bind_name(key, localized_value)
                        self._restore_reassigned_instance_member_defaults(key, localized_value)
                        continue
                    if root.startswith(_STATIC_INERT_VALUE_PREFIX):
                        self._record_statically_inert_loader_member_write(frozenset({root}), key, localized_value)
                    else:
                        self._bind_member_reference(f"{root}.{key}", localized_value)
            tracked_container = self._tracked_static_container(target.value)
            if tracked_container is not None:
                container_name, container_aliases = tracked_container
                key_resolved, item_key = _resolve_static_item_key(target.slice)
                if key_resolved:
                    self._replace_static_container_item(container_name, container_aliases, item_key, value)
                else:
                    self._mark_static_container_uncertain(
                        container_name,
                        container_aliases,
                        possible_value_node=value,
                    )
        elif isinstance(target, ast.Attribute):
            self._discard_statically_inert_class_method_binding(target)
            resolved_owner_names = self._resolve_reference_names(target.value)
            resolved_value = self._resolve_binding_value_names(value)
            resolved_owner_names = self._promote_mutated_statically_inert_loader_roots(
                resolved_owner_names or frozenset(),
                target.attr,
                value,
                resolved_value,
                invokes_setattr_dispatch=True,
            )
            syntactic_name, overwritable_target_names = self._overwritable_target_names(target)
            target_names = set(overwritable_target_names)
            if target.attr == "dict" and resolved_owner_names is not None and "builtins" in resolved_owner_names:
                target_names.add("builtins.dict")
            has_tracked_local_binding = self._has_tracked_local_static_member_binding(syntactic_name)
            if has_tracked_local_binding and syntactic_name is not None:
                target_names.add(syntactic_name)
            if syntactic_name in (
                _TRACKED_STATIC_MEMBER_REFERENCES | _STATIC_KNOWN_PRESENT_MODULE_REFERENCES
            ) and self._should_track_syntactic_static_reference(syntactic_name):
                target_names.add(syntactic_name)
            module_roots = frozenset(
                owner_name
                for owner_name in resolved_owner_names or frozenset()
                if owner_name in _TRACKED_STATIC_MODULE_ROOTS
            )
            if module_roots and not self._module_attribute_helper_has_canonical_dispatch(module_roots):
                self._invalidate_unknown_callable_side_effects()
                return
            self._record_statically_inert_loader_member_write(
                resolved_owner_names or frozenset(), target.attr, resolved_value
            )
            if not target_names:
                return
            if self._tracked_module_attribute_dispatch_is_uncertain(target_names):
                self._invalidate_unknown_callable_side_effects()
                return
            for target_name in target_names:
                if target_name == "builtins.dict":
                    self._bind_name(target_name, resolved_value)
                else:
                    self._bind_member_reference(target_name, resolved_value)
            if syntactic_name is not None:
                self._bind_name(syntactic_name, resolved_value)
                if self._non_module_scope_depth == 0:
                    class_identity_names = self._resolve_class_identity_names(value)
                    if class_identity_names:
                        self._class_identity_aliases[syntactic_name] = class_identity_names
                    else:
                        self._class_identity_aliases.pop(syntactic_name, None)
        elif isinstance(target, ast.Starred):
            # Starred unpacking (``a, *b = seq``) binds ``b`` to a list slice,
            # which is not a single static reference; drop the binding so we
            # don't carry a stale alias for any captured name.
            self._bind_target_to_value(target.value, value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
                for target_element, value_element in zip(target.elts, value.elts, strict=True):
                    self._bind_target_to_value(target_element, value_element)
            else:
                operator_accessor_names = _resolve_operator_accessor_unpacking_names(
                    value,
                    self.alias_scopes,
                    len(target.elts),
                    allow_module_locals_mapping=self._non_module_scope_depth == 0,
                    allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
                )
                if operator_accessor_names is None:
                    for name in _binding_names(target):
                        self._bind_name(name, None)
                else:
                    for target_element, resolved_names in zip(target.elts, operator_accessor_names, strict=True):
                        if isinstance(target_element, ast.Name):
                            self._bind_name(target_element.id, resolved_names)
                        else:
                            self._shadow_binding_target(target_element)

    def _overwritable_target_names(self, target: ast.Attribute) -> tuple[str | None, frozenset[str]]:
        syntactic_name = _resolve_call_name(target)
        resolved_target_names = self._resolve_reference_names(target)
        target_names = set(resolved_target_names or frozenset())
        if (
            syntactic_name is not None
            and _is_overwritable_high_risk_reference(syntactic_name)
            and self._should_track_syntactic_static_reference(syntactic_name)
        ):
            target_names.add(syntactic_name)
        if syntactic_name is not None:
            root, separator, suffix = syntactic_name.partition(".")
            root_aliases = _resolve_aliases(root, self.alias_scopes) if separator else None
            if root_aliases is not None:
                target_names.update(
                    resolved_name
                    for alias in root_aliases
                    for resolved_name in (f"{alias}.{suffix}",)
                    if _is_overwritable_high_risk_reference(resolved_name)
                )
        return syntactic_name, frozenset(
            target_name for target_name in target_names if _is_overwritable_high_risk_reference(target_name)
        )

    def _delete_target_binding(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            if id(self.alias_scopes[-1]) in self._class_scope_ids:
                self.alias_scopes[-1].pop(target.id, None)
                return
            self._bind_name(target.id, None)
        elif isinstance(target, ast.Subscript):
            registry_target_name = self._sys_modules_target_name(target)
            if registry_target_name is not None:
                self._bind_name(registry_target_name, None)
                return
            key = _resolve_static_string(target.slice)
            roots = _resolve_namespace_mapping_roots(
                target.value,
                self.alias_scopes,
                allow_module_locals_mapping=self._non_module_scope_depth == 0,
                allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
            )
            if key is not None and roots is not None:
                if self._namespace_mapping_dispatch_is_uncertain(roots):
                    self._invalidate_unknown_callable_side_effects()
                    return
                for root in roots:
                    self._delete_namespace_key(root, key)
            tracked_container = self._tracked_static_container(target.value)
            if tracked_container is not None:
                container_name, container_aliases = tracked_container
                key_resolved, item_key = _resolve_static_item_key(target.slice)
                if key_resolved:
                    self._delete_static_container_item(container_name, container_aliases, item_key)
                else:
                    self._mark_static_container_uncertain(container_name, container_aliases)
        elif isinstance(target, ast.Attribute):
            self._discard_statically_inert_class_method_binding(target)
            syntactic_name, target_names = self._overwritable_target_names(target)
            resolved_owner_names = self._resolve_reference_names(target.value)
            self._record_deleted_statically_inert_loader_member(resolved_owner_names or frozenset(), target.attr)
            module_roots = frozenset(
                owner_name
                for owner_name in resolved_owner_names or frozenset()
                if owner_name in _TRACKED_STATIC_MODULE_ROOTS
            )
            if module_roots and not self._module_attribute_helper_has_canonical_dispatch(module_roots):
                self._invalidate_unknown_callable_side_effects()
                return
            if syntactic_name in (
                _TRACKED_STATIC_MEMBER_REFERENCES | _STATIC_KNOWN_PRESENT_MODULE_REFERENCES
            ) and self._should_track_syntactic_static_reference(syntactic_name):
                target_names = frozenset({*target_names, syntactic_name})
            dynamic_target_names = {
                target_name for target_name in target_names if _is_dynamic_overwritable_high_risk_reference(target_name)
            }
            if self._tracked_module_attribute_dispatch_is_uncertain(target_names):
                self._invalidate_unknown_callable_side_effects()
                return
            if dynamic_target_names and self._restore_deleted_dynamic_target_bindings(target_names, syntactic_name):
                return
            for target_name in target_names:
                self._bind_member_reference(target_name, frozenset())
            if syntactic_name is not None and target_names:
                self._bind_member_reference(syntactic_name, frozenset())
        elif isinstance(target, ast.Starred):
            self._delete_target_binding(target.value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._delete_target_binding(element)

    def _resolve_namespace_write_call(self, node: ast.Call) -> tuple[str, frozenset[str], str, ast.AST | None] | None:
        if node.keywords:
            return None

        method_name: str
        mapping_node: ast.AST
        key_node: ast.AST
        value_node: ast.AST | None
        if isinstance(node.func, ast.Attribute) and node.func.attr in _NAMESPACE_MUTATION_METHODS:
            descriptor_name = _resolve_call_name(node.func)
            resolved_descriptor_names = (
                _apply_aliases(descriptor_name, self.alias_scopes) if descriptor_name is not None else None
            )
            is_descriptor = bool(
                resolved_descriptor_names and resolved_descriptor_names & _NAMESPACE_MUTATION_DESCRIPTORS
            )
            method_name = node.func.attr
            argument_offset = 1 if is_descriptor else 0
            if method_name in {"__setitem__", "__delitem__"}:
                expected_arg_counts = {3} if is_descriptor else {2}
                if method_name == "__delitem__":
                    expected_arg_counts = {2} if is_descriptor else {1}
            else:
                expected_arg_counts = {2, 3} if is_descriptor else {1, 2}
            if len(node.args) not in expected_arg_counts:
                return None
            mapping_node = node.args[0] if is_descriptor else node.func.value
            key_node = node.args[argument_offset]
            value_node = (
                node.args[argument_offset + 1]
                if method_name in _NAMESPACE_WRITE_METHODS and len(node.args) > argument_offset + 1
                else None
            )
        elif isinstance(node.func, ast.Name):
            resolved_descriptor_names = self._resolve_reference_names(node.func)
            for bound_method in ("__setitem__", "setdefault", "pop", "__delitem__"):
                bound_roots = {
                    resolved_name.removesuffix(f".__dict__.{bound_method}")
                    for resolved_name in resolved_descriptor_names or frozenset()
                    if resolved_name.endswith(f".__dict__.{bound_method}")
                }
                expected_lengths = {
                    "__setitem__": {2},
                    "setdefault": {1, 2},
                    "pop": {1, 2},
                    "__delitem__": {1},
                }[bound_method]
                if bound_roots and len(node.args) in expected_lengths:
                    key = _resolve_static_string(node.args[0])
                    if key is not None:
                        value_node = (
                            node.args[1] if bound_method in _NAMESPACE_WRITE_METHODS and len(node.args) > 1 else None
                        )
                        return bound_method, frozenset(bound_roots), key, value_node
            descriptor_methods = {
                resolved_name.rsplit(".", maxsplit=1)[-1]
                for resolved_name in (resolved_descriptor_names or frozenset()) & _NAMESPACE_MUTATION_DESCRIPTORS
            }
            if len(descriptor_methods) != 1:
                return None
            method_name = descriptor_methods.pop()
            expected_arg_counts = {3} if method_name == "__setitem__" else {2, 3}
            if method_name == "__delitem__":
                expected_arg_counts = {2}
            if len(node.args) not in expected_arg_counts:
                return None
            mapping_node = node.args[0]
            key_node = node.args[1]
            value_node = node.args[2] if method_name in _NAMESPACE_WRITE_METHODS and len(node.args) > 2 else None
        else:
            return None

        roots = _resolve_namespace_mapping_roots(
            mapping_node,
            self.alias_scopes,
            allow_module_locals_mapping=self._non_module_scope_depth == 0,
            allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
        )
        key = _resolve_static_string(key_node)
        if roots is None or key is None:
            return None
        return method_name, roots, key, value_node

    def _resolve_namespace_keyword_update_call(self, node: ast.Call) -> list[tuple[frozenset[str], str, ast.AST]]:
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == "update" and not node.args):
            return []
        if any(keyword.arg is None for keyword in node.keywords):
            return []
        roots = _resolve_namespace_mapping_roots(
            node.func.value,
            self.alias_scopes,
            allow_module_locals_mapping=self._non_module_scope_depth == 0,
            allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
        )
        if roots is None:
            return []
        return [(roots, keyword.arg, keyword.value) for keyword in node.keywords if keyword.arg is not None]

    @staticmethod
    def _merge_alias_values(*values: _AliasValue) -> _AliasValue:
        concrete = frozenset(alias for value in values if isinstance(value, frozenset) for alias in value)
        if concrete:
            return concrete
        if any(value is None for value in values):
            return None
        return frozenset()

    def _setdefault_value_for_key(self, root: str, key: str, default_names: _AliasValue) -> _AliasValue:
        if root in _TRACKED_MODULE_NAMESPACE_ALIASES:
            existing_names, guaranteed = _resolve_module_namespace_key_names(
                key,
                self.alias_scopes,
                allow_module_locals_mapping=self._non_module_scope_depth == 0,
            )
            if guaranteed:
                return default_names if existing_names == frozenset() else existing_names
            return self._merge_alias_values(existing_names, default_names)
        if root == _LOCAL_NAMESPACE_MAPPING_ALIAS:
            existing_names, guaranteed = _resolve_local_namespace_key_names(key, self.alias_scopes)
            if guaranteed:
                return default_names if existing_names == frozenset() else existing_names
            return self._merge_alias_values(default_names)
        if root == _SYS_MODULES_NAMESPACE_ALIAS:
            existing_names, guaranteed = _lookup_bound_alias(f"{_SYS_MODULES_BINDING_PREFIX}{key}", self.alias_scopes)
            if guaranteed:
                return default_names if existing_names == frozenset() else existing_names
            return self._merge_alias_values(existing_names, default_names)

        member_name = f"{root}.{key}"
        existing_names, guaranteed = _lookup_bound_alias(member_name, self.alias_scopes)
        if guaranteed:
            return default_names if existing_names == frozenset() else existing_names
        return self._merge_alias_values(frozenset({member_name}), default_names)

    def _delete_module_namespace_key(self, key: str) -> None:
        write_name = f"{_MODULE_NAMESPACE_WRITE_PREFIX}{key}"
        for scope in self.alias_scopes:
            scope.pop(write_name, None)
        self.alias_scopes[0].pop(key, None)
        if self._non_module_scope_depth == 0:
            for scope in self.alias_scopes[1:]:
                scope.pop(key, None)

    def _delete_namespace_key(self, root: str, key: str) -> None:
        if root in _TRACKED_MODULE_NAMESPACE_ALIASES:
            self._delete_module_namespace_key(key)
            return
        if root == _LOCAL_NAMESPACE_MAPPING_ALIAS:
            self.alias_scopes[-1].pop(key, None)
            return
        if root == _SYS_MODULES_NAMESPACE_ALIAS:
            self._bind_name(f"{_SYS_MODULES_BINDING_PREFIX}{key}", None)
            return
        self._record_deleted_statically_inert_loader_member(frozenset({root}), key)
        dotted_name = f"{root}.{key}"
        if dotted_name in (_TRACKED_STATIC_MEMBER_REFERENCES | _STATIC_KNOWN_PRESENT_MODULE_REFERENCES):
            self._bind_member_reference(dotted_name, frozenset())
            return
        for scope in self.alias_scopes:
            scope.pop(dotted_name, None)

    def _apply_static_namespace_updates(self, roots: frozenset[str], updates: list[tuple[str, ast.expr]]) -> None:
        if self._namespace_mapping_dispatch_is_uncertain(roots):
            self._invalidate_unknown_callable_side_effects()
            return
        for update_key, update_value_node in updates:
            resolved_value = self._resolve_binding_value_names(update_value_node)
            roots = self._promote_mutated_statically_inert_loader_roots(
                roots, update_key, update_value_node, resolved_value
            )
            localized_value = self._localize_instance_binding_value(update_key, update_value_node, resolved_value)
            for root in roots:
                if root in _TRACKED_MODULE_NAMESPACE_ALIASES:
                    self._bind_module_namespace_key(update_key, localized_value)
                    self._restore_reassigned_instance_member_defaults(update_key, localized_value)
                elif root == _SYS_MODULES_NAMESPACE_ALIAS:
                    if update_key in _TRACKED_STATIC_MODULE_ROOTS:
                        self._bind_name(f"{_SYS_MODULES_BINDING_PREFIX}{update_key}", resolved_value)
                elif root == _LOCAL_NAMESPACE_MAPPING_ALIAS:
                    self._bind_name(update_key, localized_value)
                    self._restore_reassigned_instance_member_defaults(update_key, localized_value)
                else:
                    self._bind_member_reference(f"{root}.{update_key}", localized_value)

    def _invalidate_unknown_namespace_updates(self, roots: frozenset[str]) -> None:
        for root in roots:
            prefix = f"{root}."
            for reference_name in _TRACKED_STATIC_MEMBER_REFERENCES:
                if reference_name.startswith(prefix):
                    self._bind_member_reference(
                        reference_name,
                        frozenset({reference_name, f"{_STATIC_UNCERTAIN_MEMBER_PREFIX}{reference_name}"}),
                    )

    def _invalidate_unknown_callable_side_effects(self) -> None:
        if self._comprehension_unknown_side_effects and self._deferred_execution_depth == 0:
            self._comprehension_unknown_side_effects[-1] = True
        self._invalidate_statically_inert_class_methods()
        self._invalidate_statically_inert_values()
        for reference_name in _TRACKED_STATIC_MEMBER_REFERENCES:
            self._bind_member_reference(
                reference_name,
                frozenset({reference_name, f"{_STATIC_UNCERTAIN_MEMBER_PREFIX}{reference_name}"}),
            )

    @staticmethod
    def _static_container_kind(aliases: frozenset[str]) -> tuple[str, str, str] | None:
        if aliases & {_STATIC_DICT_COMPLETE_ALIAS, _STATIC_DICT_UNCERTAIN_ALIAS}:
            return _STATIC_DICT_ITEM_ALIAS_PREFIX, _STATIC_DICT_COMPLETE_ALIAS, _STATIC_DICT_UNCERTAIN_ALIAS
        if aliases & {_STATIC_SEQUENCE_COMPLETE_ALIAS, _STATIC_SEQUENCE_UNCERTAIN_ALIAS}:
            return (
                _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX,
                _STATIC_SEQUENCE_COMPLETE_ALIAS,
                _STATIC_SEQUENCE_UNCERTAIN_ALIAS,
            )
        return None

    def _tracked_static_container(self, node: ast.AST | None) -> tuple[str, frozenset[str]] | None:
        target_name = _resolve_call_name(node) if node is not None else None
        target_aliases = _apply_aliases(target_name, self.alias_scopes) if target_name is not None else None
        if target_name is None or target_aliases is None or self._static_container_kind(target_aliases) is None:
            return None
        return target_name, target_aliases

    @staticmethod
    def _static_container_identities(aliases: frozenset[str]) -> frozenset[str]:
        return frozenset(alias for alias in aliases if alias.startswith(_STATIC_CONTAINER_ID_ALIAS_PREFIX))

    def _bind_mutated_static_container(
        self,
        target_name: str,
        previous_aliases: frozenset[str],
        updated_aliases: frozenset[str],
    ) -> None:
        identities = self._static_container_identities(previous_aliases)
        if len(identities) != 1:
            self._bind_name(target_name, updated_aliases)
            return
        identity = next(iter(identities))
        rebound = False
        for scope in self.alias_scopes:
            for name, value in tuple(scope.items()):
                if isinstance(value, frozenset) and identity in value:
                    scope[name] = updated_aliases
                    rebound = True
        if not rebound:
            self._bind_name(target_name, updated_aliases)

    @staticmethod
    def _static_sequence_equivalent_keys(aliases: frozenset[str], key: _StaticItemKey) -> frozenset[_StaticItemKey]:
        if not isinstance(key, (bool, int)):
            return frozenset({key})
        positive_indices: set[int] = set()
        for alias in aliases:
            decoded = _decode_operator_accessor_name(alias, _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX, 2)
            if decoded is None:
                continue
            resolved, decoded_key = _decode_operator_itemgetter_key(decoded[0])
            if resolved and isinstance(decoded_key, (bool, int)) and int(decoded_key) >= 0:
                positive_indices.add(int(decoded_key))
        if not positive_indices:
            return frozenset({key})
        item_count = max(positive_indices) + 1
        index = int(key)
        if not -item_count <= index < item_count:
            return frozenset({key})
        normalized_index = index % item_count
        return frozenset({normalized_index, normalized_index - item_count})

    def _replace_static_container_item(
        self,
        target_name: str,
        aliases: frozenset[str],
        key: _StaticItemKey,
        value_node: ast.AST,
    ) -> None:
        self._replace_static_container_item_names(
            target_name,
            aliases,
            key,
            self._resolve_binding_value_names(value_node),
        )

    def _replace_static_container_item_names(
        self,
        target_name: str,
        aliases: frozenset[str],
        key: _StaticItemKey,
        resolved_value: _AliasValue,
    ) -> None:
        kind = self._static_container_kind(aliases)
        if kind is None:
            return
        item_prefix, _complete_alias, _uncertain_alias = kind
        equivalent_keys = (
            self._static_sequence_equivalent_keys(aliases, key)
            if item_prefix == _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX
            else frozenset({key})
        )
        updated_aliases = set(aliases)
        for alias in aliases:
            decoded = _decode_operator_accessor_name(alias, item_prefix, 2)
            if decoded is None:
                continue
            resolved, decoded_key = _decode_operator_itemgetter_key(decoded[0])
            if resolved and decoded_key in equivalent_keys:
                updated_aliases.discard(alias)
        for equivalent_key in equivalent_keys:
            for value_name in resolved_value or frozenset({""}):
                updated_aliases.add(
                    _encode_operator_accessor_name(
                        item_prefix,
                        _encode_operator_itemgetter_key(equivalent_key),
                        value_name,
                    )
                )
        self._bind_mutated_static_container(target_name, aliases, frozenset(updated_aliases))

    def _delete_static_container_item(self, target_name: str, aliases: frozenset[str], key: _StaticItemKey) -> None:
        kind = self._static_container_kind(aliases)
        if kind is None:
            return
        item_prefix, complete_alias, _uncertain_alias = kind
        if item_prefix == _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX:
            sequence_items = self._static_sequence_items(aliases)
            if complete_alias not in aliases or sequence_items is None or not isinstance(key, (bool, int)):
                self._mark_static_container_uncertain(
                    target_name,
                    aliases,
                    include_existing_as_possible=True,
                )
                return
            index = int(key)
            if not -len(sequence_items) <= index < len(sequence_items):
                return
            del sequence_items[index]
            self._bind_static_sequence_items(target_name, aliases, sequence_items)
            return
        equivalent_keys = (
            self._static_sequence_equivalent_keys(aliases, key)
            if item_prefix == _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX
            else frozenset({key})
        )
        updated_aliases = set(aliases)
        for alias in aliases:
            decoded = _decode_operator_accessor_name(alias, item_prefix, 2)
            if decoded is None:
                continue
            resolved, decoded_key = _decode_operator_itemgetter_key(decoded[0])
            if resolved and decoded_key in equivalent_keys:
                updated_aliases.discard(alias)
        self._bind_mutated_static_container(target_name, aliases, frozenset(updated_aliases))

    @staticmethod
    def _static_sequence_items(aliases: frozenset[str]) -> list[frozenset[str]] | None:
        indexed_names: dict[int, set[str]] = {}
        for alias in aliases:
            decoded = _decode_operator_accessor_name(alias, _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX, 2)
            if decoded is None:
                continue
            key_resolved, key = _decode_operator_itemgetter_key(decoded[0])
            if not key_resolved or not isinstance(key, (bool, int)) or int(key) < 0:
                continue
            indexed_names.setdefault(int(key), set()).add(decoded[1])
        if not indexed_names:
            return [] if _STATIC_SEQUENCE_COMPLETE_ALIAS in aliases else None
        item_count = max(indexed_names) + 1
        if set(indexed_names) != set(range(item_count)):
            return None
        return [frozenset(indexed_names[index]) for index in range(item_count)]

    def _bind_static_sequence_items(
        self,
        target_name: str,
        previous_aliases: frozenset[str],
        items: list[frozenset[str]],
        *,
        propagate: bool = True,
    ) -> None:
        aliases = {
            _STATIC_SEQUENCE_COMPLETE_ALIAS,
            *(alias for alias in previous_aliases if alias.startswith(_STATIC_CONTAINER_ID_ALIAS_PREFIX)),
        }
        if _STATIC_MUTABLE_SEQUENCE_ALIAS in previous_aliases:
            aliases.add(_STATIC_MUTABLE_SEQUENCE_ALIAS)
        item_count = len(items)
        for index, value_names in enumerate(items):
            for equivalent_index in (index, index - item_count):
                for value_name in value_names:
                    aliases.add(
                        _encode_operator_accessor_name(
                            _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX,
                            _encode_operator_itemgetter_key(equivalent_index),
                            value_name,
                        )
                    )
        updated_aliases = frozenset(aliases)
        if propagate:
            self._bind_mutated_static_container(target_name, previous_aliases, updated_aliases)
        else:
            self._bind_name(target_name, updated_aliases)

    def _mark_static_container_uncertain(
        self,
        target_name: str,
        aliases: frozenset[str],
        *,
        possible_value_node: ast.AST | None = None,
        include_existing_as_possible: bool = False,
    ) -> None:
        kind = self._static_container_kind(aliases)
        if kind is None:
            return
        item_prefix, complete_alias, uncertain_alias = kind
        updated_aliases = set(aliases)
        updated_aliases.discard(complete_alias)
        updated_aliases.add(uncertain_alias)
        possible_names: set[str] = set()
        if include_existing_as_possible:
            for alias in aliases:
                decoded = _decode_operator_accessor_name(alias, item_prefix, 2)
                if decoded is not None and decoded[1]:
                    possible_names.add(decoded[1])
        if possible_value_node is not None:
            possible_names.update(self._resolve_binding_value_names(possible_value_node) or frozenset())
        for possible_name in possible_names:
            updated_aliases.add(
                _encode_operator_accessor_name(
                    _STATIC_CONTAINER_POSSIBLE_ITEM_ALIAS_PREFIX,
                    possible_name,
                )
            )
        self._bind_mutated_static_container(target_name, aliases, frozenset(updated_aliases))

    def _clear_static_container(self, target_name: str, aliases: frozenset[str]) -> None:
        kind = self._static_container_kind(aliases)
        if kind is None:
            return
        _item_prefix, complete_alias, _uncertain_alias = kind
        preserved_aliases = {
            alias
            for alias in aliases
            if alias.startswith(_STATIC_CONTAINER_ID_ALIAS_PREFIX) or alias == _STATIC_MUTABLE_SEQUENCE_ALIAS
        }
        self._bind_mutated_static_container(target_name, aliases, frozenset({complete_alias, *preserved_aliases}))

    def _static_container_mutation_target(
        self, node: ast.Call
    ) -> tuple[str, ast.AST, tuple[ast.expr, ...], list[ast.keyword]] | None:
        if isinstance(node.func, ast.Call) and len(node.args) == 1 and not node.keywords:
            factory_names = self._resolve_reference_names(node.func.func) or frozenset()
            factory_args = _expanded_static_call_args(node.func)
            if (
                factory_names & {"operator.methodcaller"}
                and factory_args
                and (method_name := _resolve_static_string(factory_args[0])) in _STATIC_CONTAINER_MUTATION_METHODS
                and self._tracked_static_container(node.args[0]) is not None
            ):
                return method_name, node.args[0], tuple(factory_args[1:]), node.func.keywords
        if isinstance(node.func, ast.Attribute) and node.func.attr in _STATIC_CONTAINER_MUTATION_METHODS:
            bound_target = self._tracked_static_container(node.func.value)
            if bound_target is not None:
                return node.func.attr, node.func.value, tuple(node.args), node.keywords

        resolved_method_names = self._resolve_reference_names(node.func) or frozenset()
        descriptor_methods: set[str] = set()
        for resolved_method_name in resolved_method_names:
            descriptor_root, separator, method_name = resolved_method_name.rpartition(".")
            if (
                separator
                and descriptor_root in {"dict", "builtins.dict"}
                and method_name in _STATIC_CONTAINER_MUTATION_METHODS
            ):
                descriptor_methods.add(method_name)
        if len(descriptor_methods) == 1 and node.args and self._tracked_static_container(node.args[0]) is not None:
            return next(iter(descriptor_methods)), node.args[0], tuple(node.args[1:]), node.keywords

        method_names = {
            method_name
            for method_name, _lookup_name, _fallback_name in _operator_methodcaller_fields(
                self._resolve_reference_names(node.func)
            )
            if method_name in _STATIC_CONTAINER_MUTATION_METHODS
        }
        target_node = _operator_accessor_target_node(node) if method_names else None
        if len(method_names) == 1 and target_node is not None:
            return next(iter(method_names)), target_node, (), []
        return None

    def _record_static_container_mutation(self, node: ast.Call) -> None:
        mutation = self._static_container_mutation_target(node)
        if mutation is None:
            return
        method_name, target_node, arguments, keywords = mutation
        tracked = self._tracked_static_container(target_node)
        if tracked is None:
            return
        target_name, aliases = tracked
        kind = self._static_container_kind(aliases)
        if kind is None:
            return
        item_prefix, complete_alias, _uncertain_alias = kind
        if item_prefix == _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX and _STATIC_MUTABLE_SEQUENCE_ALIAS not in aliases:
            return
        methodcaller_fields = frozenset(
            fields
            for fields in _operator_methodcaller_fields(self._resolve_reference_names(node.func))
            if fields[0] == method_name
        )

        if not arguments and methodcaller_fields:
            if method_name in {"update", "__ior__"} and item_prefix == _STATIC_DICT_ITEM_ALIAS_PREFIX:
                decoded_updates: dict[_StaticItemKey, set[str]] = {}
                for _method_name, key_field, value_name in methodcaller_fields:
                    key_resolved, key = _decode_operator_itemgetter_key(key_field)
                    if not key_resolved:
                        break
                    decoded_updates.setdefault(key, set())
                    if value_name:
                        decoded_updates[key].add(value_name)
                else:
                    for key, decoded_value_names in decoded_updates.items():
                        current_aliases = _apply_aliases(target_name, self.alias_scopes)
                        if current_aliases is None:
                            break
                        self._replace_static_container_item_names(
                            target_name,
                            current_aliases,
                            key,
                            frozenset(decoded_value_names) or None,
                        )
                    return

            lookup_fields = {lookup_field for _method_name, lookup_field, _value_name in methodcaller_fields}
            value_names = (
                frozenset(value_name for _method_name, _lookup_field, value_name in methodcaller_fields if value_name)
                or None
            )
            if len(lookup_fields) == 1:
                key_resolved, key = _decode_operator_itemgetter_key(next(iter(lookup_fields)))
                if key_resolved:
                    if method_name in {"pop", "__delitem__"}:
                        self._delete_static_container_item(target_name, aliases, key)
                        return
                    if method_name == "__setitem__":
                        self._replace_static_container_item_names(target_name, aliases, key, value_names)
                        return
                    if method_name == "setdefault":
                        existing_item = _resolve_static_container_item_names(
                            target_node,
                            key,
                            self.alias_scopes,
                            allow_module_locals_mapping=self._non_module_scope_depth == 0,
                            allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
                        )
                        if existing_item is not None and existing_item[1]:
                            return
                        self._replace_static_container_item_names(target_name, aliases, key, value_names)
                        return
                    if (
                        method_name == "insert"
                        and item_prefix == _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX
                        and complete_alias in aliases
                        and isinstance(key, (bool, int))
                    ):
                        sequence_items = self._static_sequence_items(aliases)
                        if sequence_items is not None:
                            index = int(key)
                            insertion_index = max(
                                0,
                                min(index if index >= 0 else len(sequence_items) + index, len(sequence_items)),
                            )
                            sequence_items.insert(insertion_index, value_names or frozenset({""}))
                            self._bind_static_sequence_items(target_name, aliases, sequence_items)
                            return
            if (
                method_name == "append"
                and item_prefix == _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX
                and complete_alias in aliases
            ):
                sequence_items = self._static_sequence_items(aliases)
                if sequence_items is not None:
                    sequence_items.append(value_names or frozenset({""}))
                    self._bind_static_sequence_items(target_name, aliases, sequence_items)
                    return

        if method_name == "clear" and not arguments and not keywords:
            self._clear_static_container(target_name, aliases)
            return

        if method_name in {"__setitem__", "setdefault", "pop", "__delitem__"} and not keywords:
            expected_lengths = {
                "__setitem__": {2},
                "setdefault": {1, 2},
                "pop": {0, 1} if item_prefix == _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX else {1, 2},
                "__delitem__": {1},
            }[method_name]
            if len(arguments) in expected_lengths:
                key_node = arguments[0] if arguments else ast.Constant(value=-1)
                key_resolved, key = _resolve_static_item_key(key_node)
                if key_resolved:
                    if method_name in {"pop", "__delitem__"}:
                        self._delete_static_container_item(target_name, aliases, key)
                        return
                    if method_name == "__setitem__":
                        self._replace_static_container_item(target_name, aliases, key, arguments[1])
                        return
                    existing_item = _resolve_static_container_item_names(
                        target_node,
                        key,
                        self.alias_scopes,
                        allow_module_locals_mapping=self._non_module_scope_depth == 0,
                        allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
                    )
                    if existing_item is not None and existing_item[1]:
                        return
                    default_node = arguments[1] if len(arguments) == 2 else ast.Constant(value=None)
                    if existing_item is not None and existing_item[0]:
                        self._mark_static_container_uncertain(
                            target_name,
                            aliases,
                            possible_value_node=default_node,
                        )
                    else:
                        self._replace_static_container_item(target_name, aliases, key, default_node)
                    return

        if method_name in {"update", "__ior__"} and item_prefix == _STATIC_DICT_ITEM_ALIAS_PREFIX:
            updates: list[tuple[_StaticItemKey, _AliasValue]] = []
            if len(arguments) <= 1:
                positional_updates = (
                    _resolve_static_container_update_names(
                        arguments[0],
                        self.alias_scopes,
                        allow_module_locals_mapping=self._non_module_scope_depth == 0,
                        allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
                    )
                    if arguments
                    else []
                )
                if positional_updates is not None:
                    updates.extend(positional_updates)
                    precise_keywords = True
                    for keyword in keywords:
                        if keyword.arg is not None:
                            updates.append((keyword.arg, self._resolve_binding_value_names(keyword.value)))
                            if len(updates) > _MAX_STATIC_CONTAINER_UPDATE_ITEMS:
                                precise_keywords = False
                                break
                            continue
                        expanded_updates = _resolve_static_container_update_names(
                            keyword.value,
                            self.alias_scopes,
                            allow_module_locals_mapping=self._non_module_scope_depth == 0,
                            allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
                        )
                        if expanded_updates is None:
                            precise_keywords = False
                            break
                        updates.extend(expanded_updates)
                        if len(updates) > _MAX_STATIC_CONTAINER_UPDATE_ITEMS:
                            precise_keywords = False
                            break
                    if precise_keywords:
                        for key, value_names in updates:
                            current_aliases = _apply_aliases(target_name, self.alias_scopes)
                            if current_aliases is None:
                                break
                            self._replace_static_container_item_names(
                                target_name,
                                current_aliases,
                                key,
                                value_names,
                            )
                        return

        if item_prefix == _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX and complete_alias in aliases and not keywords:
            sequence_items = self._static_sequence_items(aliases)
            if sequence_items is not None:
                if method_name == "append" and len(arguments) == 1:
                    sequence_items.append(self._resolve_binding_value_names(arguments[0]) or frozenset({""}))
                    self._bind_static_sequence_items(target_name, aliases, sequence_items)
                    return
                if method_name == "insert" and len(arguments) == 2:
                    resolved_index = _resolve_static_integer(arguments[0])
                    if resolved_index is not None:
                        insertion_index = max(
                            0,
                            min(
                                resolved_index if resolved_index >= 0 else len(sequence_items) + resolved_index,
                                len(sequence_items),
                            ),
                        )
                        sequence_items.insert(
                            insertion_index,
                            self._resolve_binding_value_names(arguments[1]) or frozenset({""}),
                        )
                        self._bind_static_sequence_items(target_name, aliases, sequence_items)
                        return
                if (
                    method_name in {"extend", "__iadd__"}
                    and len(arguments) == 1
                    and isinstance(arguments[0], (ast.List, ast.Tuple))
                ):
                    sequence_items.extend(
                        self._resolve_binding_value_names(element) or frozenset({""}) for element in arguments[0].elts
                    )
                    self._bind_static_sequence_items(target_name, aliases, sequence_items)
                    return
                if method_name == "reverse" and not arguments:
                    sequence_items.reverse()
                    self._bind_static_sequence_items(target_name, aliases, sequence_items)
                    return
                if method_name == "__imul__" and len(arguments) == 1:
                    multiplier = _resolve_static_integer(arguments[0])
                    if multiplier is not None and max(multiplier, 0) * len(sequence_items) <= 256:
                        self._bind_static_sequence_items(target_name, aliases, sequence_items * max(multiplier, 0))
                        return

        if complete_alias in aliases or self._static_container_kind(aliases) is not None:
            self._mark_static_container_uncertain(
                target_name,
                aliases,
                possible_value_node=arguments[-1] if arguments else None,
                include_existing_as_possible=item_prefix == _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX,
            )

    def _apply_resolved_namespace_item_write(
        self,
        method_name: str,
        roots: frozenset[str],
        key: str,
        value_names: _AliasValue,
    ) -> None:
        if method_name in {"pop", "__delitem__"}:
            for root in roots:
                self._delete_namespace_key(root, key)
            return
        roots = self._promote_mutated_statically_inert_loader_roots(roots, key, None, value_names)
        for root in roots:
            resolved_value = (
                self._setdefault_value_for_key(root, key, value_names) if method_name == "setdefault" else value_names
            )
            if root in _TRACKED_MODULE_NAMESPACE_ALIASES:
                self._bind_module_namespace_key(key, resolved_value)
                self._restore_reassigned_instance_member_defaults(key, resolved_value)
            elif root == _SYS_MODULES_NAMESPACE_ALIAS:
                if key in _TRACKED_STATIC_MODULE_ROOTS:
                    self._bind_name(f"{_SYS_MODULES_BINDING_PREFIX}{key}", resolved_value)
            elif root == _LOCAL_NAMESPACE_MAPPING_ALIAS:
                self._bind_name(key, resolved_value)
                self._restore_reassigned_instance_member_defaults(key, resolved_value)
            else:
                self._bind_member_reference(f"{root}.{key}", resolved_value)

    def _record_namespace_write_call(self, node: ast.Call) -> bool:
        methodcaller_fields = _operator_methodcaller_fields(self._resolve_reference_names(node.func))
        methodcaller_target = _operator_accessor_target_node(node) if methodcaller_fields else None
        methodcaller_roots = (
            _resolve_namespace_mapping_roots(
                methodcaller_target,
                self.alias_scopes,
                allow_module_locals_mapping=self._non_module_scope_depth == 0,
                allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
            )
            if methodcaller_target is not None
            else None
        )
        if methodcaller_roots is not None:
            if self._namespace_mapping_dispatch_is_uncertain(methodcaller_roots):
                self._invalidate_unknown_callable_side_effects()
                return True
            method_names = {method_name for method_name, _key, _value in methodcaller_fields}
            if len(method_names) == 1:
                method_name = next(iter(method_names))
                if method_name in {"update", "__ior__"}:
                    decoded_updates: dict[str, set[str]] = {}
                    for _method_name, key_field, value_name in methodcaller_fields:
                        key_resolved, key = _decode_operator_itemgetter_key(key_field)
                        if not key_resolved or not isinstance(key, str):
                            break
                        decoded_updates.setdefault(key, set())
                        if value_name:
                            decoded_updates[key].add(value_name)
                    else:
                        for key, decoded_value_names in decoded_updates.items():
                            self._apply_resolved_namespace_item_write(
                                method_name,
                                methodcaller_roots,
                                key,
                                frozenset(decoded_value_names) or None,
                            )
                        return True
                elif method_name in _NAMESPACE_MUTATION_METHODS:
                    decoded_keys = {
                        key
                        for _method_name, key_field, _value_name in methodcaller_fields
                        for key_resolved, key in (_decode_operator_itemgetter_key(key_field),)
                        if key_resolved and isinstance(key, str)
                    }
                    if len(decoded_keys) == 1:
                        methodcaller_value_names: _AliasValue = (
                            frozenset(
                                value_name for _method_name, _key_field, value_name in methodcaller_fields if value_name
                            )
                            or None
                        )
                        self._apply_resolved_namespace_item_write(
                            method_name,
                            methodcaller_roots,
                            next(iter(decoded_keys)),
                            methodcaller_value_names,
                        )
                        return True

        update_roots: frozenset[str] | None = None
        update_arguments = node.args
        update_methods = {"update", "__ior__"}
        syntactic_method_name = _resolve_call_name(node.func)
        resolved_method_names = (
            _apply_aliases(syntactic_method_name, self.alias_scopes) if syntactic_method_name is not None else None
        )
        descriptor_names: set[str] = set()
        for resolved_method_name in resolved_method_names or frozenset():
            if resolved_method_name not in {
                "dict.update",
                "builtins.dict.update",
                "dict.__ior__",
                "builtins.dict.__ior__",
            }:
                continue
            descriptor_root = resolved_method_name.rsplit(".", maxsplit=1)[0]
            rebound_root_names, has_rebound_root = _lookup_bound_alias(descriptor_root, self.alias_scopes)
            if not has_rebound_root or rebound_root_names == frozenset({descriptor_root}):
                descriptor_names.add(resolved_method_name)
        if descriptor_names and node.args:
            update_roots = _resolve_namespace_mapping_roots(
                node.args[0],
                self.alias_scopes,
                allow_module_locals_mapping=self._non_module_scope_depth == 0,
                allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
            )
            update_arguments = node.args[1:]
        elif isinstance(node.func, ast.Attribute) and node.func.attr in update_methods:
            resolved_attribute_methods = self._resolve_reference_names(node.func)
            attribute_descriptor_names: set[str] = set()
            for resolved_method_name in (resolved_attribute_methods or frozenset()) & {
                "dict.update",
                "builtins.dict.update",
                "dict.__ior__",
                "builtins.dict.__ior__",
            }:
                descriptor_root = resolved_method_name.rsplit(".", maxsplit=1)[0]
                rebound_root_names, has_rebound_root = _lookup_bound_alias(descriptor_root, self.alias_scopes)
                if not has_rebound_root or rebound_root_names == frozenset({descriptor_root}):
                    attribute_descriptor_names.add(resolved_method_name)
            if attribute_descriptor_names and node.args:
                update_roots = _resolve_namespace_mapping_roots(
                    node.args[0],
                    self.alias_scopes,
                    allow_module_locals_mapping=self._non_module_scope_depth == 0,
                    allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
                )
                update_arguments = node.args[1:]
            else:
                update_roots = _resolve_namespace_mapping_roots(
                    node.func.value,
                    self.alias_scopes,
                    allow_module_locals_mapping=self._non_module_scope_depth == 0,
                    allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
                )
        else:
            resolved_method_names = self._resolve_reference_names(node.func)
            if resolved_method_names is not None:
                aliased_descriptor_names = resolved_method_names & {
                    "dict.update",
                    "builtins.dict.update",
                    "dict.__ior__",
                    "builtins.dict.__ior__",
                }
                if aliased_descriptor_names and node.args:
                    update_roots = _resolve_namespace_mapping_roots(
                        node.args[0],
                        self.alias_scopes,
                        allow_module_locals_mapping=self._non_module_scope_depth == 0,
                        allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
                    )
                    update_arguments = node.args[1:]
                bound_roots = {
                    name.rsplit(".__dict__.", maxsplit=1)[0]
                    for name in resolved_method_names
                    if name.endswith((".__dict__.update", ".__dict__.__ior__"))
                }
                if bound_roots:
                    update_roots = frozenset(bound_roots)
        positional_updates = _resolve_static_namespace_update_items(update_arguments[0]) if update_arguments else []
        if (
            update_roots is not None
            and len(update_arguments) <= 1
            and positional_updates is not None
            and all(
                keyword.arg is not None
                or (
                    isinstance(keyword.value, ast.Dict)
                    and all(
                        update_key_node is not None and _resolve_static_string(update_key_node) is not None
                        for update_key_node in keyword.value.keys
                    )
                )
                for keyword in node.keywords
            )
        ):
            updates = list(positional_updates)
            for keyword in node.keywords:
                if keyword.arg is not None:
                    updates.append((keyword.arg, keyword.value))
                elif isinstance(keyword.value, ast.Dict):
                    for update_key_node, update_value_node in zip(
                        keyword.value.keys, keyword.value.values, strict=True
                    ):
                        if update_key_node is None:
                            continue
                        update_key = _resolve_static_string(update_key_node)
                        if update_key is not None:
                            updates.append((update_key, update_value_node))
            self._apply_static_namespace_updates(update_roots, updates)
            return True
        if update_roots is not None:
            self._invalidate_unknown_namespace_updates(update_roots)
            return True
        write_call = self._resolve_namespace_write_call(node)
        if write_call is None:
            return False

        method_name, roots, key, value_node = write_call
        if self._namespace_mapping_dispatch_is_uncertain(roots):
            self._invalidate_unknown_callable_side_effects()
            return True
        if method_name in {"pop", "__delitem__"}:
            for root in roots:
                self._delete_namespace_key(root, key)
            return True

        value_names = self._resolve_binding_value_names(value_node) if value_node is not None else None
        roots = self._promote_mutated_statically_inert_loader_roots(roots, key, value_node, value_names)
        for root in roots:
            resolved_value = (
                self._setdefault_value_for_key(root, key, value_names) if method_name == "setdefault" else value_names
            )
            if root in _TRACKED_MODULE_NAMESPACE_ALIASES:
                localized_value = self._localize_instance_binding_value(key, value_node, resolved_value)
                self._bind_module_namespace_key(key, localized_value)
                self._restore_reassigned_instance_member_defaults(key, localized_value)
                continue
            if root == _SYS_MODULES_NAMESPACE_ALIAS:
                if key in _TRACKED_STATIC_MODULE_ROOTS:
                    self._bind_name(f"{_SYS_MODULES_BINDING_PREFIX}{key}", resolved_value)
                continue
            if root == _LOCAL_NAMESPACE_MAPPING_ALIAS:
                localized_value = self._localize_instance_binding_value(key, value_node, resolved_value)
                self._bind_name(key, localized_value)
                self._restore_reassigned_instance_member_defaults(key, localized_value)
                continue
            self._bind_member_reference(f"{root}.{key}", resolved_value)
        return True

    def _record_setattr_call(self, node: ast.Call) -> bool:
        helper_name = _resolve_call_name(node.func)
        resolved_helper_names = _apply_aliases(helper_name, self.alias_scopes) if helper_name is not None else None
        expanded_args = _expanded_static_call_args(node)
        if expanded_args is None or not _keywords_are_all_empty_static_kwargs(node.keywords):
            return False
        target_node: ast.AST
        value_node: ast.AST
        is_bound_inert_setattr = False
        if resolved_helper_names and resolved_helper_names & {"setattr", "builtins.setattr"}:
            if len(expanded_args) != 3:
                return False
            target_node, attr_node, value_node = expanded_args
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "__setattr__":
            if len(expanded_args) != 2:
                return False
            target_node = node.func.value
            attr_node, value_node = expanded_args
            is_bound_inert_setattr = True
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "__call__"
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "__setattr__"
        ):
            if len(expanded_args) != 2:
                return False
            target_node = node.func.value.value
            attr_node, value_node = expanded_args
            is_bound_inert_setattr = True
        else:
            return False
        attr_name = _resolve_static_string(attr_node)
        if attr_name is None:
            return False
        for class_name in self._resolve_class_identity_names(target_node):
            self._bind_name(f"{_STATIC_INERT_METHOD_PREFIX}{class_name}.{attr_name}", None)
        target_roots = self._resolve_reference_names(target_node)
        if target_roots is None:
            return False
        target_is_statically_inert = self._contains_statically_inert_value(target_roots)
        if is_bound_inert_setattr and not target_is_statically_inert:
            return False
        resolved_value = self._resolve_binding_value_names(value_node)
        target_roots = self._promote_mutated_statically_inert_loader_roots(
            target_roots,
            attr_name,
            value_node,
            resolved_value,
            invokes_setattr_dispatch=True,
        )
        self._record_statically_inert_loader_member_write(target_roots, attr_name, resolved_value)
        target_names = {
            target_name
            for target_root in target_roots
            for target_name in (f"{target_root}.{attr_name}",)
            if _is_overwritable_high_risk_reference(target_name)
        }
        syntactic_target_root = _resolve_call_name(target_node)
        syntactic_target_name = f"{syntactic_target_root}.{attr_name}" if syntactic_target_root is not None else None
        if syntactic_target_name is not None and target_names:
            target_names.add(syntactic_target_name)
        for target_name in target_names:
            self._bind_member_reference(target_name, resolved_value)
        return target_is_statically_inert or (
            bool(target_names) and self._module_attribute_helper_has_canonical_dispatch(target_roots)
        )

    def _record_delattr_call(self, node: ast.Call) -> bool:
        helper_name = _resolve_call_name(node.func)
        resolved_helper_names = _apply_aliases(helper_name, self.alias_scopes) if helper_name is not None else None
        if not resolved_helper_names or not (resolved_helper_names & {"delattr", "builtins.delattr"}):
            return False
        expanded_args = _expanded_static_call_args(node)
        if expanded_args is None or len(expanded_args) != 2 or not _keywords_are_all_empty_static_kwargs(node.keywords):
            return False
        target_node = expanded_args[0]
        attr_name = _resolve_static_string(expanded_args[1])
        if attr_name is None:
            return False
        for class_name in self._resolve_class_identity_names(target_node):
            self._bind_name(f"{_STATIC_INERT_METHOD_PREFIX}{class_name}.{attr_name}", None)
        target_roots = self._resolve_reference_names(target_node)
        if target_roots is None:
            return False
        self._invalidate_noncanonical_statically_inert_loader_dispatch(
            target_node, _STATIC_CTYPES_LIBRARY_LOADER_DELETE_DISPATCH_REFERENCES
        )
        self._record_deleted_statically_inert_loader_member(target_roots, attr_name)
        target_names = {
            target_name
            for target_root in target_roots
            for target_name in (f"{target_root}.{attr_name}",)
            if _is_overwritable_high_risk_reference(target_name)
        }
        syntactic_target_root = _resolve_call_name(target_node)
        syntactic_target_name = f"{syntactic_target_root}.{attr_name}" if syntactic_target_root is not None else None
        if syntactic_target_name is not None and target_names:
            target_names.add(syntactic_target_name)
        has_canonical_dispatch = self._module_attribute_helper_has_canonical_dispatch(target_roots)
        if self._restore_deleted_dynamic_target_bindings(target_names, syntactic_target_name):
            return True
        for target_name in target_names:
            if _is_overwritable_high_risk_reference(target_name):
                self._bind_member_reference(target_name, frozenset())
        return bool(target_names) and has_canonical_dispatch

    def _module_attribute_helper_has_canonical_dispatch(self, target_roots: frozenset[str]) -> bool:
        if not target_roots or not target_roots <= _TRACKED_STATIC_MODULE_ROOTS:
            return False
        return all(
            _resolve_aliases(f"{target_root}.__class__", self.alias_scopes) == frozenset({f"{target_root}.__class__"})
            for target_root in target_roots
        )

    def _namespace_mapping_dispatch_is_uncertain(self, roots: frozenset[str]) -> bool:
        module_roots = frozenset(root for root in roots if root in _TRACKED_STATIC_MODULE_ROOTS)
        return bool(module_roots) and not self._module_attribute_helper_has_canonical_dispatch(module_roots)

    def _truthy_builtin_call_is_statically_side_effect_free(
        self, node: ast.Call, resolved_function_names: frozenset[str] | None
    ) -> bool:
        if resolved_function_names in {frozenset({"len"}), frozenset({"builtins.len"})}:
            return (
                len(node.args) == 1
                and not node.keywords
                and self._literal_class_metadata_value_is_statically_inert(node.args[0])
            )
        if resolved_function_names in {frozenset({"dict"}), frozenset({"builtins.dict"})}:
            return (
                not node.args
                and not node.keywords
                and _resolve_aliases("builtins.dict", self.alias_scopes) == frozenset({"builtins.dict"})
            )
        return False

    def _static_module_getattr_call_is_side_effect_free(
        self, node: ast.Call, resolved_function_names: frozenset[str] | None
    ) -> bool:
        if not resolved_function_names or not resolved_function_names <= {"getattr", "builtins.getattr"}:
            return False
        if "getattr" in resolved_function_names and (
            _lookup_bound_alias("getattr", self.alias_scopes)[1]
            or _resolve_aliases("builtins.getattr", self.alias_scopes) != frozenset({"builtins.getattr"})
        ):
            return False
        if node.keywords:
            return True
        if len(node.args) not in {2, 3}:
            return False
        target_roots = self._resolve_reference_names(node.args[0])
        if target_roots is None:
            return False
        if self._module_attribute_helper_has_canonical_dispatch(target_roots):
            return True
        resolved_result_names = self._resolve_reference_names(node)
        return (
            bool(target_roots)
            and all(_is_tracked_dynamic_instance_root(root) for root in target_roots)
            and resolved_result_names in {frozenset({"len"}), frozenset({"builtins.len"})}
        )

    def _static_ctypes_loader_getattribute_call_is_side_effect_free(self, node: ast.Call) -> bool:
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "__getattribute__" or node.keywords:
            return False
        if len(node.args) == 1:
            target_node = node.func.value
        elif len(node.args) == 2 and self._resolve_reference_names(node.func.value) == frozenset({"builtins.object"}):
            target_node = node.args[0]
        else:
            return False
        target_roots = self._resolve_reference_names(target_node)
        return (
            target_roots is not None
            and bool(target_roots)
            and target_roots <= _CTYPES_LIBRARY_LOADER_OBJECTS
            and self._module_attribute_helper_has_canonical_dispatch(frozenset({"ctypes"}))
        )

    def _unbound_explicit_dunder_call_is_nonexecuting(self, node: ast.Call) -> bool:
        current_func: ast.AST = node.func
        while isinstance(current_func, ast.Call):
            current_func = current_func.func
        if (
            not isinstance(current_func, ast.Attribute)
            or current_func.attr not in {"__getattr__", "__getattribute__"}
            or not isinstance(current_func.value, ast.Name)
        ):
            return False
        _binding, found = _lookup_bound_alias(current_func.value.id, self.alias_scopes)
        return not found and current_func.value.id != "object"

    def _tracked_module_attribute_dispatch_is_uncertain(self, target_names: set[str] | frozenset[str]) -> bool:
        module_roots = frozenset(
            target_name.partition(".")[0]
            for target_name in target_names
            if target_name.partition(".")[0] in _TRACKED_STATIC_MODULE_ROOTS
        )
        return bool(module_roots) and not self._module_attribute_helper_has_canonical_dispatch(module_roots)

    def _tracked_module_attribute_load_dispatch_is_uncertain(self, node: ast.Attribute) -> bool:
        owner_names = self._resolve_reference_names(node.value)
        module_roots = frozenset(
            owner_name for owner_name in owner_names or frozenset() if owner_name in _TRACKED_STATIC_MODULE_ROOTS
        )
        return bool(module_roots) and not self._module_attribute_helper_has_canonical_dispatch(module_roots)

    def _visit_truth_test(self, node: ast.AST) -> bool:
        self.visit(node)
        return self._invalidate_noncanonical_module_protocol_use(
            node, inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_TRUTH_DISPATCH_REFERENCES
        )

    def _invalidate_noncanonical_module_protocol_use(
        self, node: ast.AST, *, inert_loader_dispatch_references: frozenset[str] = frozenset()
    ) -> bool:
        if inert_loader_dispatch_references:
            self._invalidate_noncanonical_statically_inert_loader_dispatch(node, inert_loader_dispatch_references)
        resolved_names = self._resolve_reference_names(node)
        module_roots = frozenset(
            resolved_name
            for resolved_name in resolved_names or frozenset()
            if resolved_name in _TRACKED_STATIC_MODULE_ROOTS
        )
        if module_roots and not self._module_attribute_helper_has_canonical_dispatch(module_roots):
            self._invalidate_unknown_callable_side_effects()
            return True
        return False

    @staticmethod
    def _inert_loader_unary_dispatch_references(operator: ast.unaryop) -> frozenset[str]:
        member = {
            ast.UAdd: "__pos__",
            ast.USub: "__neg__",
            ast.Invert: "__invert__",
        }.get(type(operator))
        return frozenset({f"ctypes.LibraryLoader.{member}"}) if member is not None else frozenset()

    @staticmethod
    def _inert_loader_binary_dispatch_references(operator: ast.operator, *, augmented: bool = False) -> frozenset[str]:
        member = {
            ast.Add: "add",
            ast.Sub: "sub",
            ast.Mult: "mul",
            ast.MatMult: "matmul",
            ast.Div: "truediv",
            ast.FloorDiv: "floordiv",
            ast.Mod: "mod",
            ast.Pow: "pow",
            ast.LShift: "lshift",
            ast.RShift: "rshift",
            ast.BitAnd: "and",
            ast.BitXor: "xor",
            ast.BitOr: "or",
        }.get(type(operator))
        if member is None:
            return frozenset()
        prefixes = {"", "r", "i"} if augmented else {"", "r"}
        return frozenset(f"ctypes.LibraryLoader.__{prefix}{member}__" for prefix in prefixes)

    @staticmethod
    def _inert_loader_compare_dispatch_references(operator: ast.cmpop) -> frozenset[str]:
        references = {
            ast.Eq: {"__eq__"},
            ast.NotEq: {"__ne__"},
            ast.Lt: {"__lt__", "__gt__"},
            ast.LtE: {"__le__", "__ge__"},
            ast.Gt: {"__gt__", "__lt__"},
            ast.GtE: {"__ge__", "__le__"},
            ast.In: {"__contains__", "__iter__"},
            ast.NotIn: {"__contains__", "__iter__"},
        }.get(type(operator), set())
        return frozenset(f"ctypes.LibraryLoader.{reference}" for reference in references)

    def _shadow_binding_target(self, target: ast.AST) -> None:
        for name in _binding_names(target):
            self._bind_name(name, None)
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            if not self._restore_possible_qualified_high_risk_target(target):
                self._bind_target_to_value(target, ast.Constant(value=None))
        elif isinstance(target, ast.Starred):
            self._shadow_binding_target(target.value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._shadow_binding_target(element)

    def _restore_possible_qualified_high_risk_target(self, target: ast.Attribute | ast.Subscript) -> bool:
        target_names: set[str] = set()
        syntactic_name: str | None = None
        if isinstance(target, ast.Attribute):
            syntactic_name, overwritable_target_names = self._overwritable_target_names(target)
            target_names.update(overwritable_target_names)
        else:
            key = _resolve_static_string(target.slice)
            roots = _resolve_namespace_mapping_roots(
                target.value,
                self.alias_scopes,
                allow_module_locals_mapping=self._non_module_scope_depth == 0,
                allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
            )
            if key is not None and roots is not None:
                target_names.update(
                    f"{root}.{key}" for root in roots if _is_overwritable_high_risk_reference(f"{root}.{key}")
                )
        if not target_names:
            return False
        for target_name in target_names:
            self._bind_member_reference(target_name, frozenset({target_name}))
        if syntactic_name is not None:
            self._bind_name(syntactic_name, frozenset(target_names))
        return True

    def _resolve_target_bindings(self, target: ast.AST, value: ast.AST) -> _AliasScope:
        if isinstance(target, ast.Name):
            resolved_names = self._resolve_binding_value_names(value)
            return {target.id: self._localize_instance_binding_value(target.id, value, resolved_names)}
        if (
            isinstance(target, (ast.Tuple, ast.List))
            and isinstance(value, (ast.Tuple, ast.List))
            and len(target.elts) == len(value.elts)
        ):
            bindings: _AliasScope = {}
            for target_element, value_element in zip(target.elts, value.elts, strict=True):
                bindings.update(self._resolve_target_bindings(target_element, value_element))
            return bindings
        return dict.fromkeys(_binding_names(target), None)

    def _bind_comprehension_target(self, target: ast.AST, iterable: ast.AST) -> None:
        if not isinstance(iterable, (ast.Tuple, ast.List, ast.Set)):
            self._shadow_binding_target(target)
            return
        if len(iterable.elts) == 1:
            self._bind_target_to_value(target, iterable.elts[0])
            return
        branch_scopes: list[_AliasScope] = []
        for element in iterable.elts:
            branch_scope: _AliasScope = {}
            self._push_alias_scope(branch_scope)
            try:
                self._bind_target_to_value(target, element)
                branch_scopes.append(dict(branch_scope))
            finally:
                self._pop_alias_scope()
        self._merge_conditional_branch_scopes(branch_scopes)

    def _invalidate_unpacking_target_value(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, (ast.Tuple, ast.List)):
            return
        self._invalidate_noncanonical_module_protocol_use(
            value, inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_ITERATION_DISPATCH_REFERENCES
        )
        if isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
            for target_element, value_element in zip(target.elts, value.elts, strict=True):
                self._invalidate_unpacking_target_value(target_element, value_element)

    def _invalidate_iterated_unpacking_target(self, target: ast.AST, iterable: ast.AST) -> None:
        if not isinstance(target, (ast.Tuple, ast.List)):
            return
        if isinstance(iterable, (ast.Tuple, ast.List, ast.Set)):
            for element in iterable.elts:
                self._invalidate_unpacking_target_value(target, element)
        elif isinstance(iterable, ast.Dict):
            for key in iterable.keys:
                if key is not None:
                    self._invalidate_unpacking_target_value(target, key)

    def _bind_arguments(self, arguments: ast.arguments) -> None:
        positional_args = [*arguments.posonlyargs, *arguments.args]
        positional_default_start = len(positional_args) - len(arguments.defaults)
        resolved_bindings: list[tuple[str, _AliasValue]] = []
        for index, arg in enumerate(positional_args):
            default = (
                arguments.defaults[index - positional_default_start] if index >= positional_default_start else None
            )
            resolved_bindings.append(
                (
                    arg.arg,
                    self._resolve_binding_value_names(default) if default is not None else None,
                )
            )
        for arg, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True):
            resolved_bindings.append(
                (
                    arg.arg,
                    self._resolve_binding_value_names(default) if default is not None else None,
                )
            )
        for name, resolved_names in resolved_bindings:
            self._bind_name(name, resolved_names)
        if arguments.vararg is not None:
            self._bind_name(arguments.vararg.arg, None)
        if arguments.kwarg is not None:
            self._bind_name(arguments.kwarg.arg, None)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._record_import(alias, alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            return
        if node.module in _TRACKED_STATIC_MODULE_ROOTS and not self._module_attribute_helper_has_canonical_dispatch(
            frozenset({node.module})
        ):
            self._invalidate_unknown_callable_side_effects()
            for alias in node.names:
                if alias.name == "*":
                    for local_name, _import_name in _wildcard_import_aliases(node.module):
                        self._bind_name(local_name, None)
                else:
                    self._bind_name(alias.asname or alias.name, None)
            return
        for alias in node.names:
            if alias.name == "*":
                registry_binding, registry_found = _lookup_bound_alias(
                    f"{_SYS_MODULES_BINDING_PREFIX}{node.module}", self.alias_scopes
                )
                known_registry_replacement = isinstance(registry_binding, frozenset) and registry_binding != frozenset(
                    {node.module}
                )
                if known_registry_replacement:
                    assert isinstance(registry_binding, frozenset)
                    replacement_bindings: dict[str, set[str]] = {}
                    for module in registry_binding:
                        for local_name, import_name in _wildcard_import_aliases(module):
                            replacement_bindings.setdefault(local_name, set()).add(import_name)
                    for local_name, import_names in replacement_bindings.items():
                        self._bind_name(local_name, frozenset(import_names))
                    continue
                for local_name, import_name in _wildcard_import_aliases(node.module):
                    if registry_found and registry_binding is None:
                        self._bind_name(local_name, None)
                    else:
                        self._bind_name(local_name, frozenset({import_name}))
                continue
            self._record_import(alias, f"{node.module}.{alias.name}")

    def _visit_child_scope(self, body: list[ast.stmt]) -> None:
        self._push_alias_scope()
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self._pop_alias_scope()

    def _visit_conditional_branch(self, body: list[ast.stmt]) -> _AliasScope:
        branch_scope: _AliasScope = {}
        parent_is_class_scope = id(self.alias_scopes[-1]) in self._class_scope_ids
        self._push_alias_scope(branch_scope)
        if parent_is_class_scope:
            self._class_scope_ids.add(id(branch_scope))
        try:
            for statement in body:
                self.visit(statement)
            return dict(branch_scope)
        finally:
            if parent_is_class_scope:
                self._class_scope_ids.discard(id(branch_scope))
            self._pop_alias_scope()

    def _visit_conditional_expression_branch(self, node: ast.AST) -> _AliasScope:
        branch_scope: _AliasScope = {}
        self._push_alias_scope(branch_scope)
        try:
            self.visit(node)
            return dict(branch_scope)
        finally:
            self._pop_alias_scope()

    @staticmethod
    def _constant_bool(node: ast.AST) -> bool | None:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                return node.value
            if node.value is None:
                return False
            if isinstance(node.value, (int, float, complex, str, bytes)):
                return bool(node.value)
        return None

    @staticmethod
    def _literal_iter_truth(node: ast.AST) -> bool | None:
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return bool(node.elts)
        if isinstance(node, ast.Dict):
            return bool(node.keys)
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            return bool(node.value)
        return None

    def _merge_conditional_branch_scopes(self, branch_scopes: list[_AliasScope]) -> None:
        current_scope = self.alias_scopes[-1]
        branch_names = {name for scope in branch_scopes for name in scope}
        for name in branch_names:
            implicit_builtins = name == "__builtins__" and len(self.alias_scopes) == 1
            if name.startswith(_STATIC_INERT_METHOD_PREFIX):
                base_value = current_scope.get(name)
                values = [scope.get(name, base_value) for scope in branch_scopes]
                current_scope[name] = values[0] if values and all(value == values[0] for value in values) else None
                continue
            if name.startswith(_STATIC_CANONICAL_MEMBER_PREFIX):
                reference_name = name.removeprefix(_STATIC_CANONICAL_MEMBER_PREFIX)
                base_value = current_scope.get(name, frozenset({reference_name}))
            elif name.startswith(_MODULE_NAMESPACE_WRITE_PREFIX):
                key = name.removeprefix(_MODULE_NAMESPACE_WRITE_PREFIX)
                base_value, _guaranteed = _resolve_module_namespace_key_names(
                    key,
                    self.alias_scopes,
                    allow_module_locals_mapping=self._non_module_scope_depth == 0,
                )
            elif name in {"dict", "builtins.dict"}:
                base_value, found = _lookup_bound_alias(name, self.alias_scopes)
                if not found:
                    base_value = frozenset({name})
            else:
                high_risk_default = self._conditionally_overwritable_high_risk_reference_default(name)
                if high_risk_default is not None:
                    base_value = current_scope.get(name, high_risk_default)
                else:
                    base_value = current_scope.get(name, frozenset({name}) if implicit_builtins else None)
            values = [scope.get(name, base_value) for scope in branch_scopes]
            container_markers = {
                _STATIC_DICT_COMPLETE_ALIAS,
                _STATIC_DICT_UNCERTAIN_ALIAS,
                _STATIC_SEQUENCE_COMPLETE_ALIAS,
                _STATIC_SEQUENCE_UNCERTAIN_ALIAS,
            }
            if any(isinstance(value, frozenset) and value & container_markers for value in values):
                if values and all(value == values[0] for value in values):
                    current_scope[name] = values[0]
                    continue
                merged_aliases = {
                    alias
                    for value in values
                    if isinstance(value, frozenset)
                    for alias in value
                    if alias not in container_markers
                }
                if any(
                    isinstance(value, frozenset) and value & {_STATIC_DICT_COMPLETE_ALIAS, _STATIC_DICT_UNCERTAIN_ALIAS}
                    for value in values
                ):
                    merged_aliases.add(_STATIC_DICT_UNCERTAIN_ALIAS)
                if any(
                    isinstance(value, frozenset)
                    and value & {_STATIC_SEQUENCE_COMPLETE_ALIAS, _STATIC_SEQUENCE_UNCERTAIN_ALIAS}
                    for value in values
                ):
                    merged_aliases.add(_STATIC_SEQUENCE_UNCERTAIN_ALIAS)
                current_scope[name] = frozenset(merged_aliases)
                continue
            concrete_aliases = frozenset(alias for value in values if isinstance(value, frozenset) for alias in value)
            if concrete_aliases:
                current_scope[name] = concrete_aliases
            elif any(value is None for value in values):
                current_scope[name] = None

    def _conditionally_overwritable_high_risk_reference_default(self, name: str) -> _AliasValue:
        if _is_overwritable_high_risk_reference(name):
            return frozenset({name})
        root, separator, suffix = name.partition(".")
        if not separator:
            return None
        aliases = _resolve_aliases(root, self.alias_scopes)
        if aliases is None:
            return None
        resolved_high_risk_names = frozenset(
            resolved_name
            for alias in aliases
            for resolved_name in (f"{alias}.{suffix}",)
            if _is_overwritable_high_risk_reference(resolved_name)
        )
        return resolved_high_risk_names or None

    def _visit_child_scope_without_class_locals(self, body: list[ast.stmt]) -> None:
        original_scopes = self.alias_scopes
        self.alias_scopes = [scope for scope in original_scopes if id(scope) not in self._class_scope_ids]
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self.alias_scopes = original_scopes

    def _visit_class_scope(self, body: list[ast.stmt]) -> _AliasScope:
        class_scope: _AliasScope = {}
        self._push_alias_scope(class_scope)
        self._class_scope_ids.add(id(class_scope))
        self._non_module_scope_depth += 1
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self._non_module_scope_depth -= 1
            self._class_scope_ids.discard(id(class_scope))
            self._pop_alias_scope()
        for name, value in class_scope.items():
            if name.startswith(_MODULE_NAMESPACE_WRITE_PREFIX):
                self._bind_name(name, value)
                self._bind_name(name.removeprefix(_MODULE_NAMESPACE_WRITE_PREFIX), value)
            elif "." in name:
                self._bind_name(name, value)
        return class_scope

    def _visit_function_scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
            self._invalidate_noncanonical_module_protocol_use(
                decorator, inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_CALL_DISPATCH_REFERENCES
            )
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        if not self._annotations_are_postponed:
            for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
                if argument.annotation is not None:
                    self.visit(argument.annotation)
            for optional_argument in [node.args.vararg, node.args.kwarg]:
                if optional_argument is not None and optional_argument.annotation is not None:
                    self.visit(optional_argument.annotation)
            if node.returns is not None:
                self.visit(node.returns)
        self._push_alias_scope()
        try:
            self._bind_arguments(node.args)
            self._non_module_scope_depth += 1
            try:
                self._visit_child_scope_without_class_locals(node.body)
            finally:
                self._non_module_scope_depth -= 1
        finally:
            self._pop_alias_scope()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_scope(node)
        self._bind_name(node.name, None)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_scope(node)
        self._bind_name(node.name, None)

    @staticmethod
    def _is_ctypes_loader_init_alias(names: _AliasValue) -> bool:
        if names is None:
            return False
        return any(
            _strip_dunder_call_suffixes(name).removesuffix(".__init__") in _CTYPES_LIBRARY_LOADER_TYPES
            for name in names
        )

    @staticmethod
    def _class_local_method_aliases(func: ast.AST, class_scope: _AliasScope, class_name: str) -> frozenset[str]:
        if not (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in {"self", "cls", class_name}
        ):
            return frozenset()
        aliases = class_scope.get(func.attr)
        return aliases if isinstance(aliases, frozenset) else frozenset()

    @staticmethod
    def _initializer_node_calls(node: ast.AST) -> Iterator[ast.Call]:
        pending = [node]
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(node, ast.Call):
                yield node
            pending.extend(reversed(list(ast.iter_child_nodes(node))))

    def _argument_alias_scope(self, arguments: ast.arguments) -> _AliasScope:
        positional_args = [*arguments.posonlyargs, *arguments.args]
        positional_default_start = len(positional_args) - len(arguments.defaults)
        scope: _AliasScope = {}
        for index, argument in enumerate(positional_args):
            default = (
                arguments.defaults[index - positional_default_start] if index >= positional_default_start else None
            )
            scope[argument.arg] = self._resolve_binding_value_names(default) if default is not None else None
        if positional_args:
            scope[positional_args[0].arg] = frozenset({positional_args[0].arg})
        for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True):
            scope[argument.arg] = self._resolve_binding_value_names(default) if default is not None else None
        if arguments.vararg is not None:
            scope[arguments.vararg.arg] = None
        if arguments.kwarg is not None:
            scope[arguments.kwarg.arg] = None
        return scope

    def _initializer_binding_names(
        self,
        target: ast.AST,
        class_scope: _AliasScope,
        initializer_scope: _AliasScope,
        initializer_self_names: frozenset[str],
        class_name: str,
    ) -> Iterator[str]:
        yield from _binding_names(target)
        if not isinstance(target, ast.Attribute):
            return
        target_root_names = self._resolve_initializer_reference_names(
            target.value,
            class_scope,
            initializer_scope,
            class_name,
        )
        tracked_roots = initializer_self_names | frozenset({class_name})
        for root_name in target_root_names or frozenset():
            if root_name in tracked_roots:
                yield f"{root_name}.{target.attr}"

    def _delete_initializer_binding(
        self,
        target: ast.AST,
        class_scope: _AliasScope,
        initializer_scope: _AliasScope,
        class_name: str,
        initializer_self_names: frozenset[str],
    ) -> None:
        for name in self._initializer_binding_names(
            target,
            class_scope,
            initializer_scope,
            initializer_self_names,
            class_name,
        ):
            initializer_scope.pop(name, None)
        if isinstance(target, ast.Starred):
            self._delete_initializer_binding(
                target.value,
                class_scope,
                initializer_scope,
                class_name,
                initializer_self_names,
            )
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._delete_initializer_binding(
                    element,
                    class_scope,
                    initializer_scope,
                    class_name,
                    initializer_self_names,
                )

    @staticmethod
    def _initializer_import_bindings(statement: ast.Import | ast.ImportFrom) -> _AliasScope:
        bindings: _AliasScope = {}
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                local_name = alias.asname or alias.name.split(".", maxsplit=1)[0]
                bindings[local_name] = frozenset({alias.name})
            return bindings
        if statement.level != 0 or statement.module is None:
            return bindings
        for alias in statement.names:
            if alias.name == "*":
                continue
            local_name = alias.asname or alias.name
            bindings[local_name] = frozenset({f"{statement.module}.{alias.name}"})
        return bindings

    def _resolve_initializer_reference_names(
        self,
        node: ast.AST,
        class_scope: _AliasScope,
        initializer_scope: _AliasScope,
        class_name: str,
    ) -> frozenset[str] | None:
        if isinstance(node, ast.Attribute):
            value_aliases = self._resolve_initializer_reference_names(
                node.value,
                class_scope,
                initializer_scope,
                class_name,
            )
            for value_alias in value_aliases or frozenset():
                local_aliases, local_found = _lookup_bound_alias(f"{value_alias}.{node.attr}", [initializer_scope])
                if local_found:
                    return local_aliases if isinstance(local_aliases, frozenset) else None
            if value_aliases and value_aliases & frozenset({"self", "cls", class_name}):
                class_local_aliases = class_scope.get(node.attr)
                if isinstance(class_local_aliases, frozenset):
                    return class_local_aliases
        reference_name = _resolve_call_name(node)
        if reference_name is not None:
            initializer_names, initializer_found = _lookup_bound_alias(reference_name, [initializer_scope])
            if initializer_found:
                return initializer_names
        class_local_names = self._class_local_method_aliases(node, class_scope, class_name)
        if class_local_names:
            return class_local_names
        return _resolve_static_reference_names(
            node,
            [*self.alias_scopes, initializer_scope],
            allow_module_locals_mapping=self._non_module_scope_depth == 0,
            allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
        )

    def _reference_identity_names(self, node: ast.AST) -> frozenset[str]:
        names = set(self._resolve_reference_names(node) or frozenset())
        syntactic_name = _resolve_call_name(node)
        if syntactic_name is not None:
            names.add(syntactic_name)
            names.update(self._class_identity_aliases.get(syntactic_name, frozenset()))
        return frozenset(names)

    def _resolve_class_identity_names(self, node: ast.AST) -> frozenset[str]:
        reference_name = _resolve_call_name(node)
        if reference_name is None:
            return frozenset()
        identity_names = set(self._class_identity_aliases.get(reference_name, frozenset()))
        if reference_name in self._known_class_names:
            identity_names.add(reference_name)
        return frozenset(identity_names)

    def _known_class_identity_names(self, names: frozenset[str]) -> frozenset[str]:
        known_names = set(names & self._known_class_names)
        for name in names:
            known_names.update(self._class_identity_aliases.get(name, frozenset()))
        return frozenset(known_names & self._known_class_names)

    def _super_call_preserves_ctypes_loader_init(
        self,
        super_call: ast.Call,
        class_name: str,
        initializer_self_names: frozenset[str],
        base_identity_names: list[frozenset[str]],
        loader_base_indices: frozenset[int],
    ) -> bool:
        if _resolve_call_name(super_call.func) != "super" or not loader_base_indices or super_call.keywords:
            return False
        if not super_call.args:
            return any(
                not any(
                    self._base_definitely_blocks_ctypes_initializer(base_names)
                    for base_names in base_identity_names[:loader_index]
                )
                for loader_index in loader_base_indices
            )
        if len(super_call.args) != 2:
            return False
        if not self._node_is_initializer_self(super_call.args[1], initializer_self_names):
            return False
        first_arg_names = self._reference_identity_names(super_call.args[0])
        if class_name in first_arg_names:
            return any(
                not any(
                    self._base_definitely_blocks_ctypes_initializer(base_names)
                    for base_names in base_identity_names[:loader_index]
                )
                for loader_index in loader_base_indices
            )
        for index, base_names in enumerate(base_identity_names):
            if first_arg_names & base_names:
                return any(loader_index > index for loader_index in loader_base_indices)
        return False

    def _base_definitely_blocks_ctypes_initializer(self, base_names: frozenset[str]) -> bool:
        known_base_names = self._known_class_identity_names(base_names)
        if not known_base_names:
            return False
        return any(
            base_name in self._classes_with_local_initializers
            and base_name not in self._classes_with_forwarding_initializers
            for base_name in known_base_names
        )

    @staticmethod
    def _initializer_self_names(arguments: ast.arguments) -> frozenset[str]:
        positional_args = [*arguments.posonlyargs, *arguments.args]
        if not positional_args:
            return frozenset()
        return frozenset({positional_args[0].arg})

    @staticmethod
    def _node_is_initializer_self(node: ast.AST, initializer_self_names: frozenset[str]) -> bool:
        return isinstance(node, ast.Name) and node.id in initializer_self_names

    @staticmethod
    def _call_has_loader_name_argument(call: ast.Call, *, bound_method: bool) -> bool:
        # A dynamic ``*args`` / ``**kwargs`` forward (e.g. the transparent subclass
        # idiom ``def __init__(self, *args): super().__init__(*args)``) can pass the
        # library name through to the loader initializer at runtime, so treat it as
        # preserving the native load rather than requiring statically resolvable args.
        if _HighRiskPythonCallVisitor._call_forwards_dynamic_arguments(call):
            return True
        expanded_args = _expanded_static_call_args(call)
        init_arguments = _CTYPES_LOADER_INIT_ARGUMENTS[1:] if bound_method else _CTYPES_LOADER_INIT_ARGUMENTS
        keyword_values = _static_call_keyword_arguments(
            call.keywords,
            _CTYPES_LOADER_INIT_KEYWORDS - frozenset({"self"}) if bound_method else _CTYPES_LOADER_INIT_KEYWORDS,
        )
        if expanded_args is None or keyword_values is None:
            return False
        if len(expanded_args) > len(init_arguments):
            return False
        positional_names = frozenset(init_arguments[: len(expanded_args)])
        if positional_names & keyword_values.keys():
            return False
        required_positional_count = 1 if bound_method else 2
        if len(expanded_args) >= required_positional_count:
            return True
        return "name" in keyword_values

    @staticmethod
    def _call_forwards_dynamic_arguments(call: ast.Call) -> bool:
        """True when a call forwards dynamic ``*args`` / ``**kwargs`` it cannot resolve.

        Statically-known ``*(...)`` unpacks and ``**{...}`` mappings are excluded;
        those are evaluated precisely by the caller.
        """
        if any(isinstance(arg, ast.Starred) and not isinstance(arg.value, (ast.Tuple, ast.List)) for arg in call.args):
            return True
        return any(keyword.arg is None and not isinstance(keyword.value, ast.Dict) for keyword in call.keywords)

    @staticmethod
    def _node_resolves_to_initializer_self(
        node: ast.AST,
        initializer_scope: _AliasScope,
        initializer_self_names: frozenset[str],
    ) -> bool:
        reference_name = _resolve_call_name(node)
        if reference_name is None:
            return False
        resolved_names = _apply_aliases(reference_name, [initializer_scope])
        return bool(resolved_names and resolved_names & initializer_self_names)

    @staticmethod
    def _call_has_initializer_self_argument(
        call: ast.Call,
        initializer_scope: _AliasScope,
        initializer_self_names: frozenset[str],
    ) -> bool:
        # ``self`` is the first positional argument; a dynamic ``*args`` tail (e.g.
        # ``ctypes.CDLL.__init__(self, *args)``) does not change that, so validate a
        # leading concrete positional directly before requiring full static expansion.
        if call.args and not isinstance(call.args[0], ast.Starred):
            return _HighRiskPythonCallVisitor._node_resolves_to_initializer_self(
                call.args[0],
                initializer_scope,
                initializer_self_names,
            )
        expanded_args = _expanded_static_call_args(call)
        keyword_values = _static_call_keyword_arguments(call.keywords, _CTYPES_LOADER_INIT_KEYWORDS)
        if expanded_args is None or keyword_values is None:
            return False
        if expanded_args:
            return _HighRiskPythonCallVisitor._node_resolves_to_initializer_self(
                expanded_args[0],
                initializer_scope,
                initializer_self_names,
            )
        self_node = keyword_values.get("self")
        return self_node is not None and _HighRiskPythonCallVisitor._node_resolves_to_initializer_self(
            self_node,
            initializer_scope,
            initializer_self_names,
        )

    def _initializer_alias_call_is_bound(
        self,
        call: ast.Call,
        class_scope: _AliasScope,
        initializer_scope: _AliasScope,
        class_name: str,
        initializer_self_names: frozenset[str],
    ) -> bool:
        if not isinstance(call.func, ast.Attribute):
            return False
        receiver_names = self._resolve_initializer_reference_names(
            call.func.value,
            class_scope,
            initializer_scope,
            class_name,
        )
        receiver_self_names = receiver_names & initializer_self_names if receiver_names is not None else frozenset()
        if not receiver_self_names:
            return False
        for receiver_name in receiver_self_names:
            _local_aliases, local_found = _lookup_bound_alias(f"{receiver_name}.{call.func.attr}", [initializer_scope])
            if local_found:
                return False
        return isinstance(class_scope.get(call.func.attr), frozenset)

    def _initializer_call_preserves_ctypes_loader_init(
        self,
        call: ast.Call,
        class_scope: _AliasScope,
        initializer_scope: _AliasScope,
        class_name: str,
        initializer_self_names: frozenset[str],
        base_identity_names: list[frozenset[str]],
        loader_base_indices: frozenset[int],
    ) -> bool:
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "__init__"
            and isinstance(call.func.value, ast.Call)
            and self._super_call_preserves_ctypes_loader_init(
                call.func.value,
                class_name,
                initializer_self_names,
                base_identity_names,
                loader_base_indices,
            )
        ):
            return self._call_has_loader_name_argument(call, bound_method=True)
        resolved_func_names = self._resolve_initializer_reference_names(
            call.func,
            class_scope,
            initializer_scope,
            class_name,
        )
        if not self._is_ctypes_loader_init_alias(resolved_func_names):
            return False
        bound_method = self._initializer_alias_call_is_bound(
            call,
            class_scope,
            initializer_scope,
            class_name,
            initializer_self_names,
        )
        if not bound_method and not self._call_has_initializer_self_argument(
            call,
            initializer_scope,
            initializer_self_names,
        ):
            return False
        return self._call_has_loader_name_argument(call, bound_method=bound_method)

    def _initializer_node_preserves_ctypes_loader_init(
        self,
        node: ast.AST,
        class_scope: _AliasScope,
        initializer_scope: _AliasScope,
        class_name: str,
        initializer_self_names: frozenset[str],
        base_identity_names: list[frozenset[str]],
        loader_base_indices: frozenset[int],
    ) -> bool:
        return any(
            self._initializer_call_preserves_ctypes_loader_init(
                call,
                class_scope,
                initializer_scope,
                class_name,
                initializer_self_names,
                base_identity_names,
                loader_base_indices,
            )
            for call in self._initializer_node_calls(node)
        )

    def _super_call_forwards_initializer(
        self,
        super_call: ast.Call,
        class_name: str,
        initializer_self_names: frozenset[str],
    ) -> bool:
        if _resolve_call_name(super_call.func) != "super" or super_call.keywords:
            return False
        if not super_call.args:
            return True
        if len(super_call.args) != 2 or not self._node_is_initializer_self(super_call.args[1], initializer_self_names):
            return False
        return class_name in self._reference_identity_names(super_call.args[0])

    def _initializer_call_forwards_super_init(
        self,
        call: ast.Call,
        class_name: str,
        initializer_self_names: frozenset[str],
    ) -> bool:
        return (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "__init__"
            and isinstance(call.func.value, ast.Call)
            and self._super_call_forwards_initializer(call.func.value, class_name, initializer_self_names)
            and self._call_has_loader_name_argument(call, bound_method=True)
        )

    def _initializer_node_forwards_super_init(
        self,
        node: ast.AST,
        class_name: str,
        initializer_self_names: frozenset[str],
    ) -> bool:
        return any(
            self._initializer_call_forwards_super_init(call, class_name, initializer_self_names)
            for call in self._initializer_node_calls(node)
        )

    def _initializer_statements_forward_super_init(
        self,
        statements: list[ast.stmt],
        class_name: str,
        initializer_self_names: frozenset[str],
    ) -> bool:
        for statement in statements:
            if self._initializer_statement_forwards_super_init(statement, class_name, initializer_self_names):
                return True
            if self._initializer_statement_definitely_terminates(statement):
                return False
        return False

    def _initializer_statement_forwards_super_init(
        self,
        statement: ast.stmt,
        class_name: str,
        initializer_self_names: frozenset[str],
    ) -> bool:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return False
        if isinstance(statement, ast.If):
            constant_bool = self._constant_bool(statement.test)
            if constant_bool is True:
                return self._initializer_statements_forward_super_init(
                    statement.body,
                    class_name,
                    initializer_self_names,
                )
            if constant_bool is False:
                return self._initializer_statements_forward_super_init(
                    statement.orelse,
                    class_name,
                    initializer_self_names,
                )
            return self._initializer_statements_forward_super_init(
                statement.body,
                class_name,
                initializer_self_names,
            ) or self._initializer_statements_forward_super_init(
                statement.orelse,
                class_name,
                initializer_self_names,
            )
        if isinstance(statement, ast.While):
            constant_bool = self._constant_bool(statement.test)
            if constant_bool is False:
                return self._initializer_statements_forward_super_init(
                    statement.orelse,
                    class_name,
                    initializer_self_names,
                )
            return self._initializer_statements_forward_super_init(
                statement.body,
                class_name,
                initializer_self_names,
            )
        return self._initializer_node_forwards_super_init(statement, class_name, initializer_self_names)

    def _merge_initializer_branch_scopes(
        self,
        initializer_scope: _AliasScope,
        class_scope: _AliasScope,
        branch_scopes: list[_AliasScope],
    ) -> None:
        base_scope = dict(initializer_scope)
        for name in {name for scope in branch_scopes for name in scope}:
            fallback_value = base_scope.get(name)
            missing_branch_can_fall_back_to_class = False
            if name not in base_scope:
                fallback_value = self._initializer_class_fallback_alias(name, class_scope)
            branch_values: list[_AliasValue] = []
            for scope in branch_scopes:
                if name in scope:
                    branch_values.append(scope[name])
                    continue
                class_fallback = self._initializer_class_fallback_alias(name, class_scope)
                if class_fallback is not None:
                    missing_branch_can_fall_back_to_class = True
                    branch_values.append(class_fallback)
                else:
                    branch_values.append(fallback_value)
            if missing_branch_can_fall_back_to_class:
                initializer_scope.pop(name, None)
                continue
            initializer_scope[name] = self._merge_alias_values(*branch_values)

    @staticmethod
    def _initializer_class_fallback_alias(name: str, class_scope: _AliasScope) -> _AliasValue:
        self_prefixes = ("self.", "cls.")
        if not name.startswith(self_prefixes):
            return None
        _receiver, _separator, attr_name = name.partition(".")
        aliases = class_scope.get(attr_name)
        return aliases if isinstance(aliases, frozenset) else None

    def _initializer_statement_definitely_terminates(self, statement: ast.stmt) -> bool:
        if isinstance(statement, (ast.Return, ast.Raise)):
            return True
        if isinstance(statement, ast.If):
            constant_bool = self._constant_bool(statement.test)
            if constant_bool is True:
                return self._initializer_statements_definitely_terminate(statement.body)
            if constant_bool is False:
                return self._initializer_statements_definitely_terminate(statement.orelse)
            return self._initializer_statements_definitely_terminate(
                statement.body
            ) and self._initializer_statements_definitely_terminate(statement.orelse)
        return False

    def _initializer_statements_definitely_terminate(self, statements: list[ast.stmt]) -> bool:
        return any(self._initializer_statement_definitely_terminates(statement) for statement in statements)

    def _initializer_statements_preserve_ctypes_loader_init(
        self,
        statements: list[ast.stmt],
        class_scope: _AliasScope,
        initializer_scope: _AliasScope,
        class_name: str,
        initializer_self_names: frozenset[str],
        base_identity_names: list[frozenset[str]],
        loader_base_indices: frozenset[int],
    ) -> bool:
        for statement in statements:
            if self._initializer_statement_preserves_ctypes_loader_init(
                statement,
                class_scope,
                initializer_scope,
                class_name,
                initializer_self_names,
                base_identity_names,
                loader_base_indices,
            ):
                return True
            if self._initializer_statement_definitely_terminates(statement):
                return False
        return False

    def _initializer_statement_preserves_ctypes_loader_init(
        self,
        statement: ast.stmt,
        class_scope: _AliasScope,
        initializer_scope: _AliasScope,
        class_name: str,
        initializer_self_names: frozenset[str],
        base_identity_names: list[frozenset[str]],
        loader_base_indices: frozenset[int],
    ) -> bool:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return False
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            initializer_scope.update(self._initializer_import_bindings(statement))
            return False
        if isinstance(statement, ast.Delete):
            for target in statement.targets:
                self._delete_initializer_binding(
                    target,
                    class_scope,
                    initializer_scope,
                    class_name,
                    initializer_self_names,
                )
            return False
        if isinstance(statement, ast.If):
            constant_bool = self._constant_bool(statement.test)
            if constant_bool is True:
                return self._initializer_statements_preserve_ctypes_loader_init(
                    statement.body,
                    class_scope,
                    initializer_scope,
                    class_name,
                    initializer_self_names,
                    base_identity_names,
                    loader_base_indices,
                )
            if constant_bool is False:
                return self._initializer_statements_preserve_ctypes_loader_init(
                    statement.orelse,
                    class_scope,
                    initializer_scope,
                    class_name,
                    initializer_self_names,
                    base_identity_names,
                    loader_base_indices,
                )
            branch_scopes = [dict(initializer_scope), dict(initializer_scope)]
            if self._initializer_statements_preserve_ctypes_loader_init(
                statement.body,
                class_scope,
                branch_scopes[0],
                class_name,
                initializer_self_names,
                base_identity_names,
                loader_base_indices,
            ):
                return True
            if self._initializer_statements_preserve_ctypes_loader_init(
                statement.orelse,
                class_scope,
                branch_scopes[1],
                class_name,
                initializer_self_names,
                base_identity_names,
                loader_base_indices,
            ):
                return True
            self._merge_initializer_branch_scopes(initializer_scope, class_scope, branch_scopes)
            return False
        if isinstance(statement, ast.While):
            constant_bool = self._constant_bool(statement.test)
            if constant_bool is False:
                return self._initializer_statements_preserve_ctypes_loader_init(
                    statement.orelse,
                    class_scope,
                    initializer_scope,
                    class_name,
                    initializer_self_names,
                    base_identity_names,
                    loader_base_indices,
                )
            branch_scope = dict(initializer_scope)
            if self._initializer_statements_preserve_ctypes_loader_init(
                statement.body,
                class_scope,
                branch_scope,
                class_name,
                initializer_self_names,
                base_identity_names,
                loader_base_indices,
            ):
                return True
            self._merge_initializer_branch_scopes(
                initializer_scope, class_scope, [branch_scope, dict(initializer_scope)]
            )
            return False
        if isinstance(statement, ast.Assign):
            if self._initializer_node_preserves_ctypes_loader_init(
                statement.value,
                class_scope,
                initializer_scope,
                class_name,
                initializer_self_names,
                base_identity_names,
                loader_base_indices,
            ):
                return True
            resolved_value = self._resolve_initializer_reference_names(
                statement.value,
                class_scope,
                initializer_scope,
                class_name,
            )
            for target in statement.targets:
                for name in self._initializer_binding_names(
                    target,
                    class_scope,
                    initializer_scope,
                    initializer_self_names,
                    class_name,
                ):
                    initializer_scope[name] = resolved_value
            return False
        if isinstance(statement, ast.AnnAssign):
            if statement.value is None:
                for name in self._initializer_binding_names(
                    statement.target,
                    class_scope,
                    initializer_scope,
                    initializer_self_names,
                    class_name,
                ):
                    initializer_scope[name] = None
                return False
            if self._initializer_node_preserves_ctypes_loader_init(
                statement.value,
                class_scope,
                initializer_scope,
                class_name,
                initializer_self_names,
                base_identity_names,
                loader_base_indices,
            ):
                return True
            resolved_value = self._resolve_initializer_reference_names(
                statement.value,
                class_scope,
                initializer_scope,
                class_name,
            )
            for name in self._initializer_binding_names(
                statement.target,
                class_scope,
                initializer_scope,
                initializer_self_names,
                class_name,
            ):
                initializer_scope[name] = resolved_value
            return False
        return self._initializer_node_preserves_ctypes_loader_init(
            statement,
            class_scope,
            initializer_scope,
            class_name,
            initializer_self_names,
            base_identity_names,
            loader_base_indices,
        )

    @staticmethod
    def _class_method(node: ast.ClassDef, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        for statement in reversed(node.body):
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name == name:
                return statement
            if _HighRiskPythonCallVisitor._class_statement_binds_name(statement, name):
                return None
        return None

    @staticmethod
    def _class_statement_binds_name(statement: ast.stmt, name: str) -> bool:
        if isinstance(statement, ast.Assign):
            return any(bound_name == name for target in statement.targets for bound_name in _binding_names(target))
        if isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
            return any(bound_name == name for bound_name in _binding_names(statement.target))
        if isinstance(statement, ast.Delete):
            return any(bound_name == name for target in statement.targets for bound_name in _binding_names(target))
        return False

    def _class_method_has_decorator(
        self,
        method: ast.FunctionDef | ast.AsyncFunctionDef,
        decorator_names: frozenset[str],
    ) -> bool:
        for decorator in method.decorator_list:
            if _resolve_call_name(decorator) in decorator_names:
                return True
            resolved_names = self._resolve_reference_names(decorator)
            if resolved_names is not None and resolved_names & decorator_names:
                return True
        return False

    @staticmethod
    def _method_body_is_statically_inert(method: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        return all(
            isinstance(statement, ast.Pass)
            or (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            )
            for statement in method.body
        )

    @staticmethod
    def _literal_class_metadata_value_is_statically_inert(value: ast.AST) -> bool:
        if isinstance(value, ast.Constant):
            return True
        if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
            return all(
                _HighRiskPythonCallVisitor._literal_class_metadata_value_is_statically_inert(item)
                for item in value.elts
            )
        if isinstance(value, ast.Dict):
            return all(
                key is not None
                and _HighRiskPythonCallVisitor._literal_class_metadata_value_is_statically_inert(key)
                and _HighRiskPythonCallVisitor._literal_class_metadata_value_is_statically_inert(item)
                for key, item in zip(value.keys, value.values, strict=True)
            )
        return False

    @staticmethod
    def _class_metadata_annotation_is_statically_inert(annotation: ast.AST) -> bool:
        return (
            isinstance(annotation, ast.Name) and annotation.id in {"bool", "bytes", "float", "int", "object", "str"}
        ) or (isinstance(annotation, ast.Constant) and isinstance(annotation.value, str))

    def _record_statically_inert_class_methods(self, node: ast.ClassDef, class_scope: _AliasScope) -> None:
        if len(self.alias_scopes) != 1 or node.decorator_list or node.bases or node.keywords:
            return
        if _resolve_aliases("builtins.__build_class__", self.alias_scopes) != frozenset({"builtins.__build_class__"}):
            return
        method_names = {
            statement.name for statement in node.body if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for class_statement in node.body:
            if isinstance(class_statement, ast.Pass) or (
                isinstance(class_statement, ast.Expr)
                and isinstance(class_statement.value, ast.Constant)
                and isinstance(class_statement.value.value, str)
            ):
                continue
            if (
                isinstance(class_statement, ast.Assign)
                and all(
                    isinstance(target, ast.Name) and target.id not in method_names | {"staticmethod", "classmethod"}
                    for target in class_statement.targets
                )
                and self._literal_class_metadata_value_is_statically_inert(class_statement.value)
            ):
                continue
            if (
                isinstance(class_statement, ast.AnnAssign)
                and isinstance(class_statement.target, ast.Name)
                and class_statement.target.id not in method_names | {"staticmethod", "classmethod"}
                and (
                    class_statement.value is None
                    or self._literal_class_metadata_value_is_statically_inert(class_statement.value)
                )
                and self._class_metadata_annotation_is_statically_inert(class_statement.annotation)
            ):
                continue
            if not isinstance(class_statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return
            if not self._method_body_is_statically_inert(class_statement):
                return
            if not self._class_method_has_unshadowed_builtin_dispatch(class_statement, class_scope):
                return
        for method_name in method_names:
            statement = self._class_method(node, method_name)
            if statement is None:
                continue
            if not self._method_body_is_statically_inert(statement):
                continue
            if self._class_method_has_unshadowed_builtin_dispatch(statement, class_scope):
                inert_name = f"{node.name}.{statement.name}"
                self._bind_name(f"{_STATIC_INERT_METHOD_PREFIX}{inert_name}", frozenset({inert_name}))

    def _class_method_has_unshadowed_builtin_dispatch(
        self, method: ast.FunctionDef | ast.AsyncFunctionDef, class_scope: _AliasScope
    ) -> bool:
        if len(method.decorator_list) != 1:
            return False
        for decorator in method.decorator_list:
            reference_name = _resolve_call_name(decorator)
            if reference_name not in {"staticmethod", "classmethod"}:
                continue
            if reference_name in class_scope:
                return False
            _binding, found = _lookup_bound_alias(reference_name, self.alias_scopes)
            canonical_name = f"builtins.{reference_name}"
            if not found and _resolve_aliases(canonical_name, self.alias_scopes) == frozenset({canonical_name}):
                return True
        return False

    def _is_statically_inert_class_method_call(self, func: ast.AST) -> bool:
        if not isinstance(func, ast.Attribute):
            return False
        class_names = self._resolve_class_identity_names(func.value)
        return bool(class_names) and all(
            _lookup_bound_alias(f"{_STATIC_INERT_METHOD_PREFIX}{class_name}.{func.attr}", self.alias_scopes)
            == (frozenset({f"{class_name}.{func.attr}"}), True)
            for class_name in class_names
        )

    def _discard_statically_inert_class_method_binding(self, target: ast.Attribute) -> None:
        for class_name in self._resolve_class_identity_names(target.value):
            self._bind_name(f"{_STATIC_INERT_METHOD_PREFIX}{class_name}.{target.attr}", None)

    def _discard_statically_inert_class_bindings(self, class_name: str) -> None:
        inert_prefix = f"{_STATIC_INERT_METHOD_PREFIX}{class_name}."
        inert_names = {name for scope in self.alias_scopes for name in scope if name.startswith(inert_prefix)}
        for inert_name in inert_names:
            self._bind_name(inert_name, None)

    def _invalidate_statically_inert_class_methods(self) -> None:
        inert_names = {
            name for scope in self.alias_scopes for name in scope if name.startswith(_STATIC_INERT_METHOD_PREFIX)
        }
        for inert_name in inert_names:
            self._bind_name(inert_name, None)

    @staticmethod
    def _contains_statically_inert_value(names: _AliasValue) -> bool:
        return isinstance(names, frozenset) and any(name.startswith(_STATIC_INERT_VALUE_PREFIX) for name in names)

    @staticmethod
    def _promoted_statically_inert_loader_root(root: str) -> str:
        suffix = root.removeprefix(_STATIC_INERT_CTYPES_LIBRARY_LOADER)
        return f"{_CTYPES_LIBRARY_LOADER_INSTANCE_ROOT}{suffix}"

    def _statically_inert_loader_write_is_safe(
        self, member_name: str, value: ast.AST | None, resolved_value: _AliasValue
    ) -> bool:
        if not self._statically_inert_loader_dispatch_is_canonical(
            _STATIC_CTYPES_LIBRARY_LOADER_MUTATION_DISPATCH_REFERENCES
        ):
            return False
        if resolved_value in {frozenset({"len"}), frozenset({"builtins.len"})}:
            return True
        return (
            member_name != "_dlltype"
            and value is not None
            and (
                self._literal_class_metadata_value_is_statically_inert(value)
                or (
                    isinstance(value, ast.Call)
                    and not value.args
                    and not value.keywords
                    and (
                        self._resolve_reference_names(value.func) == frozenset({"builtins.object"})
                        or (
                            self._resolve_reference_names(value.func)
                            in {frozenset({"dict"}), frozenset({"builtins.dict"})}
                            and _resolve_aliases("builtins.dict", self.alias_scopes) == frozenset({"builtins.dict"})
                        )
                    )
                )
            )
        )

    def _statically_inert_loader_dispatch_is_canonical(self, dispatch_references: frozenset[str]) -> bool:
        return all(
            _resolve_aliases(reference, self.alias_scopes) == frozenset({reference})
            for reference in dispatch_references
        )

    def _record_statically_inert_loader_member_write(
        self, roots: frozenset[str], member_name: str, resolved_value: _AliasValue
    ) -> None:
        for root in roots:
            if root.startswith(_STATIC_INERT_VALUE_PREFIX):
                self._bind_name(f"{_STATIC_INERT_MEMBER_STATUS_PREFIX}{root}.{member_name}", frozenset({"present"}))
                self._bind_name(f"{root}.{member_name}", resolved_value)

    def _record_deleted_statically_inert_loader_member(self, roots: frozenset[str], member_name: str) -> None:
        for root in roots:
            if root.startswith(_STATIC_INERT_VALUE_PREFIX):
                self._bind_name(f"{_STATIC_INERT_MEMBER_STATUS_PREFIX}{root}.{member_name}", frozenset({"deleted"}))
                self._bind_name(f"{root}.{member_name}", frozenset())

    def _statically_inert_loader_member_was_deleted(self, roots: frozenset[str], member_name: str) -> bool:
        return any(
            root.startswith(_STATIC_INERT_VALUE_PREFIX)
            and _lookup_bound_alias(f"{_STATIC_INERT_MEMBER_STATUS_PREFIX}{root}.{member_name}", self.alias_scopes)
            == (frozenset({"deleted"}), True)
            for root in roots
        )

    def _statically_inert_loader_member_is_present(self, roots: frozenset[str], member_name: str) -> bool:
        return any(
            root.startswith(_STATIC_INERT_VALUE_PREFIX)
            and _lookup_bound_alias(f"{_STATIC_INERT_MEMBER_STATUS_PREFIX}{root}.{member_name}", self.alias_scopes)
            == (frozenset({"present"}), True)
            for root in roots
        )

    def _invalidate_noncanonical_statically_inert_loader_dispatch(
        self, target: ast.AST, dispatch_references: frozenset[str]
    ) -> None:
        target_names = self._resolve_reference_names(target)
        if self._contains_statically_inert_value(
            target_names
        ) and not self._statically_inert_loader_dispatch_is_canonical(dispatch_references):
            self._invalidate_unknown_callable_side_effects()

    def _statically_present_inert_loader_reflective_read(
        self, node: ast.Call
    ) -> tuple[ast.AST, frozenset[str], frozenset[str]] | None:
        helper_names = self._resolve_reference_names(node.func)
        is_getattr = bool(helper_names and helper_names <= {"getattr", "builtins.getattr"})
        is_hasattr = bool(helper_names and helper_names <= {"hasattr", "builtins.hasattr"})
        if not (is_getattr or is_hasattr) or node.keywords:
            return None
        expected_arg_counts = {2, 3} if is_getattr else {2}
        if len(node.args) not in expected_arg_counts:
            return None
        target_node, attr_node = node.args[:2]
        attr_name = _resolve_static_string(attr_node)
        target_names = self._resolve_reference_names(target_node) or frozenset()
        inert_roots = frozenset(root for root in target_names if root.startswith(_STATIC_INERT_VALUE_PREFIX))
        if attr_name is None or not inert_roots:
            return None
        is_present = (
            attr_name in _CTYPES_LIBRARY_LOADER_NON_LOADING_ATTRIBUTES
            and not self._statically_inert_loader_member_was_deleted(inert_roots, attr_name)
        ) or self._statically_inert_loader_member_is_present(inert_roots, attr_name)
        if not is_present:
            return None
        resolved_names: set[str] = set()
        if is_getattr:
            for root in inert_roots:
                member_names, found = _lookup_bound_alias(f"{root}.{attr_name}", self.alias_scopes)
                if found and isinstance(member_names, frozenset):
                    resolved_names.update(member_names)
        return (
            target_node,
            frozenset(resolved_names),
            _STATIC_CTYPES_LIBRARY_LOADER_EXISTING_ATTRIBUTE_DISPATCH_REFERENCES,
        )

    def _promote_mutated_statically_inert_loader_roots(
        self,
        roots: frozenset[str],
        member_name: str,
        value: ast.AST | None,
        resolved_value: _AliasValue,
        *,
        invokes_setattr_dispatch: bool = False,
    ) -> frozenset[str]:
        inert_roots = frozenset(root for root in roots if root.startswith(_STATIC_INERT_VALUE_PREFIX))
        if (
            inert_roots
            and invokes_setattr_dispatch
            and not self._statically_inert_loader_dispatch_is_canonical(
                _STATIC_CTYPES_LIBRARY_LOADER_MUTATION_DISPATCH_REFERENCES
            )
        ):
            self._invalidate_unknown_callable_side_effects()
        if not inert_roots or self._statically_inert_loader_write_is_safe(member_name, value, resolved_value):
            return roots
        class_roots = frozenset(root for root in inert_roots if root.endswith(".__class__"))
        self._invalidate_statically_inert_values(
            None if class_roots else frozenset(root.removesuffix(".__class__") for root in inert_roots)
        )
        return frozenset(
            self._promoted_statically_inert_loader_root(root) if root in inert_roots else root for root in roots
        )

    def _invalidate_statically_inert_values(self, invalidated_roots: frozenset[str] | None = None) -> None:
        visible_names = {name for scope in self.alias_scopes for name in scope}
        for name in visible_names:
            resolved_names, found = _lookup_bound_alias(name, self.alias_scopes)
            if found and isinstance(resolved_names, frozenset):
                matching_roots = frozenset(
                    root
                    for root in resolved_names
                    if root.startswith(_STATIC_INERT_VALUE_PREFIX)
                    and (invalidated_roots is None or root in invalidated_roots)
                )
                if not matching_roots:
                    continue
                # After an escape or unsafe mutation, fail closed as a loader with
                # an executable member instead of dropping the object identity.
                self._bind_name(
                    name,
                    frozenset(
                        (resolved_names - matching_roots)
                        | {self._promoted_statically_inert_loader_root(root) for root in matching_roots}
                    ),
                )

    def _class_has_local_initializer(
        self,
        node: ast.ClassDef,
        class_scope: _AliasScope,
        init_method: ast.FunctionDef | ast.AsyncFunctionDef | None,
    ) -> bool:
        return init_method is not None or "__init__" in class_scope

    def _class_initializer_forwards_super_init(
        self,
        node: ast.ClassDef,
        init_method: ast.FunctionDef | ast.AsyncFunctionDef | None,
    ) -> bool:
        if init_method is None or isinstance(init_method, ast.AsyncFunctionDef):
            return False
        if self._class_method_has_decorator(
            init_method,
            frozenset(
                {
                    "staticmethod",
                    "builtins.staticmethod",
                    "classmethod",
                    "builtins.classmethod",
                }
            ),
        ):
            return False
        return self._initializer_statements_forward_super_init(
            init_method.body,
            node.name,
            self._initializer_self_names(init_method.args),
        )

    @staticmethod
    def _return_value_is_obvious_non_instance(value: ast.AST | None) -> bool:
        if value is None:
            return True
        if isinstance(value, ast.Call) and _resolve_call_name(value.func) == "object":
            return True
        if isinstance(value, ast.Constant):
            return True
        return isinstance(value, (ast.Tuple, ast.List, ast.Dict, ast.Set))

    def _class_new_may_skip_init(self, node: ast.ClassDef) -> bool:
        new_method = self._class_method(node, "__new__")
        if new_method is None:
            return False
        if isinstance(new_method, ast.AsyncFunctionDef):
            return True
        _may_continue, may_return_instance = self._new_statements_flow(new_method.body)
        return not may_return_instance

    def _new_statements_flow(self, statements: list[ast.stmt]) -> tuple[bool, bool]:
        may_continue = True
        may_return_instance = False
        for statement in statements:
            if not may_continue:
                break
            if isinstance(statement, ast.Return):
                return False, may_return_instance or not self._return_value_is_obvious_non_instance(statement.value)
            if isinstance(statement, ast.If):
                statement_may_continue, statement_may_return_instance = self._new_if_flow(statement)
                may_continue = statement_may_continue
                may_return_instance = may_return_instance or statement_may_return_instance
                continue
            # try/for/while/with bodies may conditionally execute a nested ``return``;
            # an instance-returning return inside them still runs the inherited
            # initializer, so the block must not be assumed to skip ``__init__``.
            for nested_body in self._new_nested_statement_bodies(statement):
                _, nested_may_return_instance = self._new_statements_flow(nested_body)
                may_return_instance = may_return_instance or nested_may_return_instance
        return may_continue, may_return_instance

    @staticmethod
    def _new_nested_statement_bodies(statement: ast.stmt) -> list[list[ast.stmt]]:
        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            return [statement.body, statement.orelse]
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            return [statement.body]
        if isinstance(statement, ast.Try):
            return [
                statement.body,
                *(handler.body for handler in statement.handlers),
                statement.orelse,
                statement.finalbody,
            ]
        return []

    def _new_if_flow(self, statement: ast.If) -> tuple[bool, bool]:
        constant_bool = self._constant_bool(statement.test)
        if constant_bool is True:
            return self._new_statements_flow(statement.body)
        if constant_bool is False:
            return self._new_statements_flow(statement.orelse)
        body_may_continue, body_may_return_instance = self._new_statements_flow(statement.body)
        orelse_may_continue, orelse_may_return_instance = self._new_statements_flow(statement.orelse)
        return body_may_continue or orelse_may_continue, body_may_return_instance or orelse_may_return_instance

    def _class_preserves_ctypes_loader_init(self, node: ast.ClassDef, class_scope: _AliasScope) -> bool:
        base_identity_names = [self._reference_identity_names(base) for base in node.bases]
        loader_base_indices = frozenset(
            index
            for index, base_names in enumerate(base_identity_names)
            if _canonical_ctypes_loader_type_aliases(base_names)
        )
        init_method = self._class_method(node, "__init__")
        if self._class_new_may_skip_init(node):
            return False
        if isinstance(init_method, ast.AsyncFunctionDef) or (
            init_method is not None
            and self._class_method_has_decorator(
                init_method,
                frozenset({"staticmethod", "builtins.staticmethod", "classmethod", "builtins.classmethod"}),
            )
        ):
            return False
        if init_method is None:
            if "__init__" in class_scope:
                return self._is_ctypes_loader_init_alias(class_scope.get("__init__"))
            if not node.bases:
                return False
            return any(
                not any(
                    self._base_definitely_blocks_ctypes_initializer(base_names)
                    for base_names in base_identity_names[:loader_index]
                )
                for loader_index in loader_base_indices
            )
        initializer_scope = self._argument_alias_scope(init_method.args)
        initializer_self_names = self._initializer_self_names(init_method.args)
        return self._initializer_statements_preserve_ctypes_loader_init(
            init_method.body,
            class_scope,
            initializer_scope,
            node.name,
            initializer_self_names,
            base_identity_names,
            loader_base_indices,
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._discard_statically_inert_class_bindings(node.name)
        base_ctypes_loader_aliases = frozenset(
            alias
            for base in node.bases
            for alias in _canonical_ctypes_loader_type_aliases(self._resolve_reference_names(base))
        )
        for decorator in node.decorator_list:
            self.visit(decorator)
            self._invalidate_noncanonical_module_protocol_use(
                decorator, inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_CALL_DISPATCH_REFERENCES
            )
        for base in node.bases:
            self.visit(base)
            self._invalidate_noncanonical_module_protocol_use(
                base, inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_MRO_DISPATCH_REFERENCES
            )
        for keyword in node.keywords:
            self.visit(keyword)
            dispatch_references = (
                _STATIC_CTYPES_LIBRARY_LOADER_CALL_DISPATCH_REFERENCES
                if keyword.arg == "metaclass"
                else (
                    _STATIC_CTYPES_LIBRARY_LOADER_MAPPING_EXPANSION_DISPATCH_REFERENCES
                    if keyword.arg is None
                    else frozenset()
                )
            )
            self._invalidate_noncanonical_module_protocol_use(
                keyword.value, inert_loader_dispatch_references=dispatch_references
            )
        class_scope = self._visit_class_scope(node.body)
        self._known_class_names.add(node.name)
        self._class_identity_aliases[node.name] = frozenset({node.name})
        self._record_statically_inert_class_methods(node, class_scope)
        init_method = self._class_method(node, "__init__")
        if self._class_has_local_initializer(node, class_scope, init_method):
            self._classes_with_local_initializers.add(node.name)
        if self._class_initializer_forwards_super_init(node, init_method):
            self._classes_with_forwarding_initializers.add(node.name)
        ctypes_loader_type_aliases = (
            base_ctypes_loader_aliases if self._class_preserves_ctypes_loader_init(node, class_scope) else frozenset()
        )
        self._bind_name(node.name, ctypes_loader_type_aliases or None)

    @staticmethod
    def _match_pattern_uses_subject_protocol(pattern: ast.pattern) -> bool:
        if isinstance(pattern, (ast.MatchValue, ast.MatchSequence, ast.MatchMapping, ast.MatchClass)):
            return True
        if isinstance(pattern, ast.MatchAs):
            return pattern.pattern is not None and _HighRiskPythonCallVisitor._match_pattern_uses_subject_protocol(
                pattern.pattern
            )
        if isinstance(pattern, ast.MatchOr):
            return any(
                _HighRiskPythonCallVisitor._match_pattern_uses_subject_protocol(option) for option in pattern.patterns
            )
        return False

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        if any(self._match_pattern_uses_subject_protocol(case.pattern) for case in node.cases):
            self._invalidate_noncanonical_module_protocol_use(
                node.subject, inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_MATCH_DISPATCH_REFERENCES
            )
        branch_scopes: list[_AliasScope] = []
        for case in node.cases:
            self.visit(case.pattern)
            if case.guard is not None:
                self._visit_truth_test(case.guard)
            branch_scopes.append(self._visit_conditional_branch(case.body))
        branch_scopes.append({})
        self._merge_conditional_branch_scopes(branch_scopes)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        self._push_alias_scope()
        try:
            self._bind_arguments(node.args)
            self._non_module_scope_depth += 1
            self._deferred_execution_depth += 1
            try:
                self.visit(node.body)
            finally:
                self._deferred_execution_depth -= 1
                self._non_module_scope_depth -= 1
        finally:
            self._pop_alias_scope()

    def _visit_comprehension(
        self,
        generators: list[ast.comprehension],
        result_nodes: list[ast.AST],
        *,
        inline_module_scope: bool,
        eager_body: bool = True,
        hashed_result_nodes: tuple[ast.AST, ...] = (),
    ) -> None:
        if not generators:
            return
        self.visit(generators[0].iter)
        self._invalidate_noncanonical_module_protocol_use(
            generators[0].iter,
            inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_ITERATION_DISPATCH_REFERENCES,
        )
        if self._literal_iter_truth(generators[0].iter) is False:
            return
        outer_scope_index = len(self.alias_scopes) - 1
        self._push_alias_scope()
        self._comprehension_outer_scope_indices.append(outer_scope_index)
        self._comprehension_unknown_side_effects.append(False)
        has_module_locals = inline_module_scope and self._non_module_scope_depth == 0
        if not has_module_locals:
            self._non_module_scope_depth += 1
        try:
            first_generator, *remaining_generators = generators
            self._invalidate_iterated_unpacking_target(first_generator.target, first_generator.iter)
            self._bind_comprehension_target(first_generator.target, first_generator.iter)
            self.visit(first_generator.target)
            for condition in first_generator.ifs:
                self._visit_truth_test(condition)
            for generator in remaining_generators:
                self.visit(generator.iter)
                self._invalidate_noncanonical_module_protocol_use(
                    generator.iter,
                    inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_ITERATION_DISPATCH_REFERENCES,
                )
                self._invalidate_iterated_unpacking_target(generator.target, generator.iter)
                self._bind_comprehension_target(generator.target, generator.iter)
                self.visit(generator.target)
                for condition in generator.ifs:
                    self._visit_truth_test(condition)
            for result_node in result_nodes:
                self.visit(result_node)
                if any(result_node is hashed_result_node for hashed_result_node in hashed_result_nodes):
                    self._invalidate_noncanonical_module_protocol_use(
                        result_node,
                        inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_HASH_DISPATCH_REFERENCES,
                    )
        finally:
            if not has_module_locals:
                self._non_module_scope_depth -= 1
            has_unknown_side_effects = self._comprehension_unknown_side_effects.pop()
            self._comprehension_outer_scope_indices.pop()
            self._pop_alias_scope()
        if has_unknown_side_effects and eager_body:
            self._invalidate_unknown_callable_side_effects()

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, [node.elt], inline_module_scope=False)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(
            node.generators,
            [node.elt],
            inline_module_scope=False,
            hashed_result_nodes=(node.elt,),
        )

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node.generators, [node.elt], inline_module_scope=False, eager_body=False)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(
            node.generators,
            [node.key, node.value],
            inline_module_scope=False,
            hashed_result_nodes=(node.key,),
        )

    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values, strict=True):
            if key is not None:
                self.visit(key)
                self._invalidate_noncanonical_module_protocol_use(
                    key, inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_HASH_DISPATCH_REFERENCES
                )
            self.visit(value)
            if key is None:
                self._invalidate_noncanonical_module_protocol_use(
                    value,
                    inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_MAPPING_EXPANSION_DISPATCH_REFERENCES,
                )

    def visit_Set(self, node: ast.Set) -> None:
        for element in node.elts:
            self.visit(element)
            self._invalidate_noncanonical_module_protocol_use(
                element, inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_HASH_DISPATCH_REFERENCES
            )

    def visit_Starred(self, node: ast.Starred) -> None:
        self.visit(node.value)
        if isinstance(node.ctx, ast.Load):
            self._invalidate_noncanonical_module_protocol_use(
                node.value,
                inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_ITERATION_DISPATCH_REFERENCES,
            )

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self._invalidate_unpacking_target_value(target, node.value)
            self._bind_target_to_value(target, node.value)
            self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.annotation is not None and not self._annotations_are_postponed:
            self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
            self._bind_target_to_value(node.target, node.value)
        else:
            self._shadow_binding_target(node.target)
        self.visit(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        dispatch_references = self._inert_loader_binary_dispatch_references(node.op, augmented=True)
        self._invalidate_noncanonical_module_protocol_use(
            node.target, inert_loader_dispatch_references=dispatch_references
        )
        self._invalidate_noncanonical_module_protocol_use(
            node.value, inert_loader_dispatch_references=dispatch_references
        )
        if isinstance(node.op, ast.BitOr):
            roots = _resolve_namespace_mapping_roots(
                node.target,
                self.alias_scopes,
                allow_module_locals_mapping=self._non_module_scope_depth == 0,
                allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
            )
            updates = _resolve_static_namespace_update_items(node.value)
            if roots is not None and updates is not None:
                self._apply_static_namespace_updates(roots, updates)
                self.visit(node.target)
                return
            if roots is not None:
                self._invalidate_unknown_namespace_updates(roots)
                self.visit(node.target)
                return
            tracked_container = self._tracked_static_container(node.target)
            if tracked_container is not None:
                synthetic_call = ast.Call(
                    func=ast.Attribute(value=node.target, attr="__ior__", ctx=ast.Load()),
                    args=[node.value],
                    keywords=[],
                )
                self._record_static_container_mutation(synthetic_call)
                self.visit(node.target)
                return
        if isinstance(node.op, (ast.Add, ast.Mult)):
            tracked_container = self._tracked_static_container(node.target)
            if tracked_container is not None:
                target_name, aliases = tracked_container
                kind = self._static_container_kind(aliases)
                if kind is not None and kind[0] == _STATIC_SEQUENCE_ITEM_ALIAS_PREFIX:
                    method_name = "__iadd__" if isinstance(node.op, ast.Add) else "__imul__"
                    if _STATIC_MUTABLE_SEQUENCE_ALIAS in aliases:
                        synthetic_call = ast.Call(
                            func=ast.Attribute(value=node.target, attr=method_name, ctx=ast.Load()),
                            args=[node.value],
                            keywords=[],
                        )
                        self._record_static_container_mutation(synthetic_call)
                        self.visit(node.target)
                        return

                    sequence_items = self._static_sequence_items(aliases)
                    if sequence_items is not None:
                        rebound_items: list[frozenset[str]] | None = None
                        if isinstance(node.op, ast.Add) and isinstance(node.value, ast.Tuple):
                            rebound_items = [
                                *sequence_items,
                                *(
                                    self._resolve_binding_value_names(element) or frozenset({""})
                                    for element in node.value.elts
                                ),
                            ]
                        elif isinstance(node.op, ast.Mult):
                            multiplier = _resolve_static_integer(node.value)
                            if multiplier is not None and max(multiplier, 0) * len(sequence_items) <= 256:
                                rebound_items = sequence_items * max(multiplier, 0)
                        if rebound_items is not None:
                            self._static_container_generation += 1
                            rebound_aliases = frozenset(
                                {f"{_STATIC_CONTAINER_ID_ALIAS_PREFIX}{self._static_container_generation}"}
                            )
                            self._bind_static_sequence_items(
                                target_name,
                                rebound_aliases,
                                rebound_items,
                                propagate=False,
                            )
                            self.visit(node.target)
                            return
        resolved_names = self._resolve_reference_names(node.target)
        if resolved_names is not None:
            for resolved_name in resolved_names:
                normalized_name = _ctypes_loader_attribute_load_name(resolved_name)
                if normalized_name is not None:
                    self.risky_calls.add(normalized_name)
        self._shadow_binding_target(node.target)
        self.visit(node.target)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                self._invalidate_noncanonical_statically_inert_loader_dispatch(
                    target.value, _STATIC_CTYPES_LIBRARY_LOADER_DELETE_DISPATCH_REFERENCES
                )
            elif isinstance(target, ast.Subscript):
                self._invalidate_noncanonical_statically_inert_loader_dispatch(
                    target.value, _STATIC_CTYPES_LIBRARY_LOADER_ITEM_DELETE_DISPATCH_REFERENCES
                )
            self._delete_target_binding(target)
            if isinstance(target, ast.Attribute):
                resolved_owner_names = self._resolve_reference_names(target.value)
                if target.attr == "dict" and resolved_owner_names is not None and "builtins" in resolved_owner_names:
                    self._bind_name("builtins.dict", None)
            self.visit(target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        if isinstance(node.target, ast.Name) and self._comprehension_outer_scope_indices:
            self._bind_name_in_scope(
                self._comprehension_outer_scope_indices[-1],
                node.target.id,
                self._resolve_binding_value_names(node.value),
            )
        else:
            self._bind_target_to_value(node.target, node.value)
        self.visit(node.target)

    def _visit_loop(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        dispatch_references = (
            _STATIC_CTYPES_LIBRARY_LOADER_ASYNC_ITERATION_DISPATCH_REFERENCES
            if isinstance(node, ast.AsyncFor)
            else _STATIC_CTYPES_LIBRARY_LOADER_ITERATION_DISPATCH_REFERENCES
        )
        self._invalidate_noncanonical_module_protocol_use(
            node.iter, inert_loader_dispatch_references=dispatch_references
        )
        iter_truth = self._literal_iter_truth(node.iter)
        if iter_truth is False:
            for statement in node.orelse:
                self.visit(statement)
            return

        self._invalidate_iterated_unpacking_target(node.target, node.iter)
        body_scope: _AliasScope = {}
        self._push_alias_scope(body_scope)
        try:
            # Bind the loop variable to the union of a literal iterable's elements
            # (e.g. ``for lib in [ctypes.cdll]: lib.msvcrt``); non-literal iterables
            # still shadow the target.
            self._bind_comprehension_target(node.target, node.iter)
            self.visit(node.target)
            for statement in node.body:
                self.visit(statement)
            if (
                isinstance(node.iter, (ast.List, ast.Tuple))
                and node.iter.elts
                and all(isinstance(statement, ast.Pass) for statement in node.body)
            ):
                self._bind_target_to_value(node.target, node.iter.elts[-1])
            body_scope = dict(body_scope)
        finally:
            self._pop_alias_scope()
        branch_scopes = [body_scope]
        if iter_truth is not True:
            branch_scopes.append({})
        self._merge_conditional_branch_scopes(branch_scopes)
        for statement in node.orelse:
            self.visit(statement)

    def visit_For(self, node: ast.For) -> None:
        self._visit_loop(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_loop(node)

    def visit_While(self, node: ast.While) -> None:
        self._visit_truth_test(node.test)
        constant_bool = self._constant_bool(node.test)
        if constant_bool is False:
            for statement in node.orelse:
                self.visit(statement)
            return

        branch_scopes = [self._visit_conditional_branch(node.body)]
        if node.orelse:
            branch_scopes.append(self._visit_conditional_branch(node.orelse))
        else:
            branch_scopes.append({})
        self._merge_conditional_branch_scopes(branch_scopes)

    def visit_If(self, node: ast.If) -> None:
        self._visit_truth_test(node.test)
        constant_bool = self._constant_bool(node.test)
        if constant_bool is True:
            for statement in node.body:
                self.visit(statement)
            return
        if constant_bool is False:
            for statement in node.orelse:
                self.visit(statement)
            return

        branch_scopes = [self._visit_conditional_branch(node.body)]
        branch_scopes.append(self._visit_conditional_branch(node.orelse) if node.orelse else {})
        self._merge_conditional_branch_scopes(branch_scopes)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self._visit_truth_test(node.test)
        condition_value = _statically_known_truth_value(node.test, self.alias_scopes)
        if condition_value is not None:
            self.visit(node.body if condition_value else node.orelse)
            return
        self._merge_conditional_branch_scopes(
            [
                self._visit_conditional_expression_branch(node.body),
                self._visit_conditional_expression_branch(node.orelse),
            ]
        )

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        for index, value in enumerate(node.values):
            self.visit(value)
            if index == len(node.values) - 1:
                return
            self._invalidate_noncanonical_module_protocol_use(
                value, inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_TRUTH_DISPATCH_REFERENCES
            )
            truth_value = _statically_known_truth_value(value, self.alias_scopes)
            short_circuits = (isinstance(node.op, ast.Or) and truth_value is True) or (
                isinstance(node.op, ast.And) and truth_value is False
            )
            if short_circuits:
                return
            definitely_continues = (isinstance(node.op, ast.Or) and truth_value is False) or (
                isinstance(node.op, ast.And) and truth_value is True
            )
            if definitely_continues:
                continue
            remaining = ast.BoolOp(op=node.op, values=node.values[index + 1 :])
            self._merge_conditional_branch_scopes([self._visit_conditional_expression_branch(remaining), {}])
            return

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if isinstance(node.op, ast.Not):
            self._visit_truth_test(node.operand)
            return
        self.visit(node.operand)
        self._invalidate_noncanonical_module_protocol_use(
            node.operand, inert_loader_dispatch_references=self._inert_loader_unary_dispatch_references(node.op)
        )

    def visit_BinOp(self, node: ast.BinOp) -> None:
        self.visit(node.left)
        self.visit(node.right)
        dispatch_references = self._inert_loader_binary_dispatch_references(node.op)
        self._invalidate_noncanonical_module_protocol_use(
            node.left, inert_loader_dispatch_references=dispatch_references
        )
        self._invalidate_noncanonical_module_protocol_use(
            node.right, inert_loader_dispatch_references=dispatch_references
        )

    def visit_Compare(self, node: ast.Compare) -> None:
        self.visit(node.left)
        left = node.left
        for operator, comparator in zip(node.ops, node.comparators, strict=True):
            self.visit(comparator)
            if not isinstance(operator, (ast.Is, ast.IsNot)):
                dispatch_references = self._inert_loader_compare_dispatch_references(operator)
                self._invalidate_noncanonical_module_protocol_use(
                    left, inert_loader_dispatch_references=dispatch_references
                )
                self._invalidate_noncanonical_module_protocol_use(
                    comparator, inert_loader_dispatch_references=dispatch_references
                )
            left = comparator

    def visit_FormattedValue(self, node: ast.FormattedValue) -> None:
        self.visit(node.value)
        self._invalidate_noncanonical_module_protocol_use(
            node.value, inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_FORMAT_DISPATCH_REFERENCES
        )
        if node.format_spec is not None:
            self.visit(node.format_spec)

    def visit_Await(self, node: ast.Await) -> None:
        self.visit(node.value)
        self._invalidate_noncanonical_module_protocol_use(
            node.value, inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_AWAIT_DISPATCH_REFERENCES
        )

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        self.visit(node.value)
        self._invalidate_noncanonical_module_protocol_use(
            node.value, inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_ITERATION_DISPATCH_REFERENCES
        )

    def visit_Slice(self, node: ast.Slice) -> None:
        for value in (node.lower, node.upper, node.step):
            if value is not None:
                self.visit(value)
                self._invalidate_noncanonical_module_protocol_use(
                    value, inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_INDEX_DISPATCH_REFERENCES
                )

    def visit_Assert(self, node: ast.Assert) -> None:
        self._visit_truth_test(node.test)
        if node.msg is not None:
            self.visit(node.msg)

    def visit_Try(self, node: ast.Try) -> None:
        branch_scopes = [self._visit_conditional_branch([*node.body, *node.orelse])]
        for handler in node.handlers:
            if handler.type is not None:
                self.visit(handler.type)
            branch_scope: _AliasScope = {}
            self._push_alias_scope(branch_scope)
            try:
                if handler.name is not None:
                    self._bind_name(handler.name, None)
                for statement in handler.body:
                    self.visit(statement)
                branch_scope = dict(branch_scope)
            finally:
                self._pop_alias_scope()
            branch_scopes.append(branch_scope)
        self._merge_conditional_branch_scopes(branch_scopes)
        for statement in node.finalbody:
            self.visit(statement)

    def _visit_with(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            dispatch_references = (
                _STATIC_CTYPES_LIBRARY_LOADER_ASYNC_CONTEXT_DISPATCH_REFERENCES
                if isinstance(node, ast.AsyncWith)
                else _STATIC_CTYPES_LIBRARY_LOADER_CONTEXT_DISPATCH_REFERENCES
            )
            self._invalidate_noncanonical_module_protocol_use(
                item.context_expr, inert_loader_dispatch_references=dispatch_references
            )
            if item.optional_vars is not None:
                bound_value: ast.AST | None = None
                has_bound_value = False
                if isinstance(item.context_expr, ast.Call) and self._resolve_reference_names(
                    item.context_expr.func
                ) == frozenset({"contextlib.nullcontext"}):
                    if len(item.context_expr.args) == 1 and not item.context_expr.keywords:
                        bound_value = item.context_expr.args[0]
                        has_bound_value = True
                    elif (
                        not item.context_expr.args
                        and len(item.context_expr.keywords) == 1
                        and item.context_expr.keywords[0].arg == "enter_result"
                    ):
                        bound_value = item.context_expr.keywords[0].value
                        has_bound_value = True
                if not has_bound_value or bound_value is None:
                    self._shadow_binding_target(item.optional_vars)
                else:
                    self._invalidate_unpacking_target_value(item.optional_vars, bound_value)
                    self._bind_target_to_value(item.optional_vars, bound_value)
                self.visit(item.optional_vars)
        for statement in node.body:
            self.visit(statement)

    def visit_With(self, node: ast.With) -> None:
        self._visit_with(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_with(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name is not None:
            self._bind_name(node.name, None)
        for statement in node.body:
            self.visit(statement)

    def visit_Call(self, node: ast.Call) -> None:
        if self._noncanonical_module_namespace_roots(node):
            self._invalidate_unknown_callable_side_effects()
        self._invalidate_noncanonical_statically_inert_loader_dispatch(
            node.func, _STATIC_CTYPES_LIBRARY_LOADER_CALL_DISPATCH_REFERENCES
        )
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"LoadLibrary", "__getitem__"}:
            dispatch_references = (
                _STATIC_CTYPES_LIBRARY_LOADER_LOAD_LIBRARY_DISPATCH_REFERENCES
                if node.func.attr == "LoadLibrary"
                else _STATIC_CTYPES_LIBRARY_LOADER_ITEM_DISPATCH_REFERENCES
            )
            self._invalidate_noncanonical_statically_inert_loader_dispatch(node.func.value, dispatch_references)
        modeled_statically_present_reflective_read = self._statically_present_inert_loader_reflective_read(node)
        if modeled_statically_present_reflective_read is not None:
            target_node, _member_names, dispatch_references = modeled_statically_present_reflective_read
            self._invalidate_noncanonical_statically_inert_loader_dispatch(target_node, dispatch_references)
        risky_call_count_before = len(self.risky_calls)
        call_result_names = (
            modeled_statically_present_reflective_read[1]
            if modeled_statically_present_reflective_read is not None
            else self._resolve_reference_names(node)
        )
        if call_result_names is not None:
            self._call_result_aliases[id(node)] = call_result_names
            for call_result_name in call_result_names:
                normalized_result_name = _ctypes_loader_attribute_load_name(call_result_name)
                if normalized_result_name is not None:
                    self.risky_calls.add(normalized_result_name)

        direct_call_name = _resolve_call_name(node.func)
        if direct_call_name is not None:
            direct_call_head = direct_call_name.split(".", maxsplit=1)[0]
            direct_head_names = _resolve_aliases(direct_call_head, self.alias_scopes)
            normalized_direct_name = _normalized_high_risk_python_call_name(direct_call_name)
            if (
                normalized_direct_name is not None
                and direct_head_names == frozenset({direct_call_head})
                and not _has_static_overwritable_reference_prefix(direct_call_name)
            ):
                self.risky_calls.add(normalized_direct_name)

        resolved_names = self._resolve_reference_names(node.func)
        if resolved_names is None:
            resolved_names = frozenset()
        eagerly_consumes_generators = bool(resolved_names & _STATIC_EAGER_GENERATOR_CONSUMER_REFERENCES)
        for resolved_name in resolved_names:
            normalized_name = _normalized_high_risk_python_call_name(resolved_name)
            if normalized_name is not None:
                self.risky_calls.add(normalized_name)
        operator_method_names = _resolve_operator_methodcaller_invoked_method_names(
            node,
            self.alias_scopes,
            allow_module_locals_mapping=self._non_module_scope_depth == 0,
            allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
        )
        for operator_method_name in operator_method_names or frozenset():
            normalized_name = _normalized_high_risk_python_call_name(operator_method_name)
            if normalized_name is not None:
                self.risky_calls.add(normalized_name)
        self.visit(node.func)
        for argument in node.args:
            if (
                eagerly_consumes_generators
                and isinstance(argument, ast.GeneratorExp)
                and self._generator_direct_body_is_guaranteed(argument)
            ):
                self._eager_comprehension_depth += 1
                try:
                    self.visit(argument)
                finally:
                    self._eager_comprehension_depth -= 1
            else:
                self.visit(argument)
        for keyword in node.keywords:
            self.visit(keyword.value)
            if keyword.arg is None:
                self._invalidate_noncanonical_module_protocol_use(
                    keyword.value,
                    inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_MAPPING_EXPANSION_DISPATCH_REFERENCES,
                )
        if self._is_statically_inert_loader_construction(
            node
        ) and not self._statically_inert_loader_dispatch_is_canonical(
            _STATIC_CTYPES_LIBRARY_LOADER_CONSTRUCTION_DISPATCH_REFERENCES
        ):
            self._invalidate_unknown_callable_side_effects()
        modeled_namespace_mutation = self._record_namespace_write_call(node)
        modeled_static_helper_mutation = self._record_setattr_call(node) or self._record_delattr_call(node)
        resolved_function_names = self._resolve_reference_names(node.func)
        modeled_truthy_builtin_call = self._truthy_builtin_call_is_statically_side_effect_free(
            node, resolved_function_names
        )
        modeled_static_module_getattr_call = self._static_module_getattr_call_is_side_effect_free(
            node, resolved_function_names
        )
        modeled_static_ctypes_loader_getattribute_call = (
            self._static_ctypes_loader_getattribute_call_is_side_effect_free(node)
        )
        modeled_statically_present_reflective_call = (
            modeled_statically_present_reflective_read is not None
            and self._statically_inert_loader_dispatch_is_canonical(modeled_statically_present_reflective_read[2])
        )
        modeled_unbound_explicit_dunder_call = self._unbound_explicit_dunder_call_is_nonexecuting(node)
        namespace_lookup_roots = (
            _resolve_namespace_mapping_roots(
                node,
                self.alias_scopes,
                allow_module_locals_mapping=self._non_module_scope_depth == 0,
                allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
            )
            if resolved_function_names and resolved_function_names <= {"vars", "builtins.vars"}
            else None
        )
        modeled_static_namespace_lookup = namespace_lookup_roots is not None and (
            self._module_attribute_helper_has_canonical_dispatch(namespace_lookup_roots)
        )
        modeled_reported_high_risk_call = bool(
            len(self.risky_calls) > risky_call_count_before
            or (
                resolved_function_names
                and any(
                    _normalized_high_risk_python_call_name(resolved_name) is not None
                    for resolved_name in resolved_function_names
                )
            )
        )
        modeled_eager_generator_call = bool(
            resolved_function_names
            and resolved_function_names <= _STATIC_EAGER_GENERATOR_CONSUMER_REFERENCES
            and node.args
            and all(isinstance(argument, ast.GeneratorExp) for argument in node.args)
            and not node.keywords
        )
        modeled_statically_inert_value_call = self._contains_statically_inert_value(resolved_function_names)
        known_modeled_call_names = (
            _STATIC_OVERWRITABLE_HIGH_RISK_REFERENCES
            | _STATIC_SIDE_EFFECT_FREE_BUILTIN_REFERENCES
            | _STATIC_DISPATCH_DECORATOR_REFERENCES
            | _STATIC_CONTEXT_MANAGER_HELPER_REFERENCES
            | _STATIC_OPERATOR_ACCESSOR_HELPER_REFERENCES
        )
        if (
            not modeled_namespace_mutation
            and not modeled_static_helper_mutation
            and not modeled_truthy_builtin_call
            and not modeled_static_module_getattr_call
            and not modeled_static_ctypes_loader_getattribute_call
            and not modeled_statically_present_reflective_call
            and not modeled_unbound_explicit_dunder_call
            and not modeled_static_namespace_lookup
            and not modeled_reported_high_risk_call
            and not modeled_eager_generator_call
            and not modeled_statically_inert_value_call
            and not self._is_statically_inert_class_method_call(node.func)
            and (not resolved_function_names or not resolved_function_names <= known_modeled_call_names)
        ):
            self._invalidate_unknown_callable_side_effects()
        self._record_static_container_mutation(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        dispatch_references = (
            _STATIC_CTYPES_LIBRARY_LOADER_ITEM_DISPATCH_REFERENCES
            if isinstance(node.ctx, ast.Load)
            else (
                _STATIC_CTYPES_LIBRARY_LOADER_ITEM_STORE_DISPATCH_REFERENCES
                if isinstance(node.ctx, ast.Store)
                else _STATIC_CTYPES_LIBRARY_LOADER_ITEM_DELETE_DISPATCH_REFERENCES
            )
        )
        self._invalidate_noncanonical_statically_inert_loader_dispatch(node.value, dispatch_references)
        self._invalidate_noncanonical_module_protocol_use(node.value)
        self._invalidate_noncanonical_module_protocol_use(
            node.slice, inert_loader_dispatch_references=_STATIC_CTYPES_LIBRARY_LOADER_INDEX_DISPATCH_REFERENCES
        )
        if isinstance(node.ctx, ast.Load):
            resolved_names = self._resolve_reference_names(node)
            if resolved_names is not None:
                for resolved_name in resolved_names:
                    normalized_name = _normalized_high_risk_python_call_name(resolved_name)
                    if normalized_name is not None:
                        self.risky_calls.add(normalized_name)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, ast.Load):
            owner_names = self._resolve_reference_names(node.value) or frozenset()
            dispatch_references = (
                _STATIC_CTYPES_LIBRARY_LOADER_EXISTING_ATTRIBUTE_DISPATCH_REFERENCES
                if (
                    node.attr in _CTYPES_LIBRARY_LOADER_NON_LOADING_ATTRIBUTES
                    and not self._statically_inert_loader_member_was_deleted(owner_names, node.attr)
                )
                or self._statically_inert_loader_member_is_present(owner_names, node.attr)
                or node.attr == "LoadLibrary"
                else _STATIC_CTYPES_LIBRARY_LOADER_ATTRIBUTE_DISPATCH_REFERENCES
            )
            self._invalidate_noncanonical_statically_inert_loader_dispatch(node.value, dispatch_references)
            if self._noncanonical_module_namespace_roots(
                node
            ) or self._tracked_module_attribute_load_dispatch_is_uncertain(node):
                self._invalidate_unknown_callable_side_effects()
            resolved_names = self._resolve_reference_names(node)
            if resolved_names is not None:
                for resolved_name in resolved_names:
                    normalized_name = _ctypes_loader_attribute_load_name(resolved_name)
                    if normalized_name is not None:
                        self.risky_calls.add(normalized_name)
        self.generic_visit(node)


def high_risk_python_calls_in_tree(tree: ast.AST) -> set[HighRiskPythonCall]:
    """Return high-risk calls resolvable from an already parsed Python tree."""
    visitor = _HighRiskPythonCallVisitor()
    visitor.visit(tree)
    return {
        HighRiskPythonCall(name=name, rule_code=_rule_code_for_high_risk_call(name)) for name in visitor.risky_calls
    }


def high_risk_python_calls_in_source(source_bytes: bytes) -> set[HighRiskPythonCall]:
    """Return the set of high-risk Python calls resolvable from ``source_bytes``.

    Passes ``source_bytes`` to ``ast.parse`` directly so PEP 263 encoding
    declarations (``# -*- coding: latin-1 -*-``) are honored instead of being
    lossily replaced before parsing.

    Raises:
        PythonArchiveMemberParseError: when the source cannot be parsed or
            analysis exceeds the interpreter recursion limit (deeply nested
            source). Callers fail closed by marking the scan incomplete rather
            than letting a crafted member crash the scan or silently pass.
    """
    try:
        tree = ast.parse(source_bytes)
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise PythonArchiveMemberParseError(str(exc)) from exc

    try:
        return high_risk_python_calls_in_tree(tree)
    except RecursionError as exc:
        raise PythonArchiveMemberParseError(f"analysis exceeded recursion limit: {exc}") from exc


_PYTHON_MEMBER_CHECK_NAME = "Python Archive Member Security"
_EXECUTABLE_MEMBER_CHECK_NAME = "Executable Archive Member Detection"


def _add_python_archive_member_call_checks(
    *,
    archive_kind: str,
    archive_path: str,
    member_name: str,
    result: ScanResult,
    calls: set[HighRiskPythonCall],
) -> bool:
    if not calls:
        return False

    # Emit one finding per rule code so SARIF consumers, dashboards, and
    # per-rule severity overrides see accurate attribution (``os.system``
    # as S101, ``subprocess.run`` as S103, etc.) instead of one S104
    # catch-all that aggregates unrelated risk categories.
    calls_by_rule: dict[str, list[str]] = {}
    for call in calls:
        calls_by_rule.setdefault(call.rule_code, []).append(call.name)
    for rule_code in sorted(calls_by_rule):
        names = sorted(calls_by_rule[rule_code])
        reason = f"high-risk calls: {', '.join(names)}"
        severity = IssueSeverity.CRITICAL if rule_code in {"S109", "S110"} else IssueSeverity.WARNING
        result.add_check(
            name=_PYTHON_MEMBER_CHECK_NAME,
            passed=False,
            message=f"High-risk Python code found in {archive_kind} member {member_name}: {reason}",
            severity=severity,
            location=f"{archive_path}:{member_name}",
            details={"entry": member_name, "reason": reason},
            rule_code=rule_code,
        )
    return True


def _add_executable_archive_member_check(
    *,
    archive_kind: str,
    archive_path: str,
    member_name: str,
    result: ScanResult,
) -> None:
    result.add_check(
        name=_EXECUTABLE_MEMBER_CHECK_NAME,
        passed=False,
        message=f"Executable file found in {archive_kind} archive: {member_name}",
        severity=IssueSeverity.WARNING,
        location=f"{archive_path}:{member_name}",
        details={"entry": member_name},
    )


def _add_incomplete_executable_archive_member_check(
    *,
    archive_kind: str,
    archive_path: str,
    member_name: str,
    result: ScanResult,
    incomplete_reason: str,
) -> None:
    mark_archive_scan_incomplete(result, incomplete_reason)
    result.add_check(
        name=_EXECUTABLE_MEMBER_CHECK_NAME,
        passed=False,
        message=f"Executable content probe was inconclusive for {archive_kind} archive member: {member_name}",
        severity=IssueSeverity.INFO,
        location=f"{archive_path}:{member_name}",
        details={"entry": member_name, "analysis_incomplete": True},
    )


def scan_archive_member_for_known_risks(
    *,
    archive_kind: str,
    archive_path: str,
    member_name: str,
    tmp_path: str | None,
    total_size: int,
    result: ScanResult,
    max_python_analysis_bytes: int,
    python_analysis_incomplete_reason: str,
    executable_analysis_incomplete_reason: str,
    analyze_python_source: bool = True,
    analyze_executable_content: bool = True,
    sniff_python_source: bool = False,
) -> None:
    """Inspect generic archive members that nested dispatch would otherwise ignore.

    ``archive_kind`` is a short label (``"ZIP"`` / ``"TAR"`` / ``"NeMo"``) used only for the
    human-readable message text. The dispatcher (1) routes Python-looking
    members through bounded AST analysis unless content routing already owns
    the member, (2) flags native/script executable-suffix members, and (3)
    leaves everything else to the caller's normal nested routing.
    """
    normalized_name = member_name.replace("\\", "/").lstrip("/")
    normalized_lower = normalized_name.lower()
    location = f"{archive_path}:{member_name}"

    if is_python_archive_member_name(normalized_lower) and analyze_python_source:
        if total_size > max_python_analysis_bytes:
            mark_archive_scan_incomplete(result, python_analysis_incomplete_reason)
            result.add_check(
                name=_PYTHON_MEMBER_CHECK_NAME,
                passed=False,
                message=f"Python archive member too large for bounded security analysis: {member_name}",
                severity=IssueSeverity.INFO,
                location=location,
                details={
                    "entry": member_name,
                    "file_size": total_size,
                    "max_scan_bytes": max_python_analysis_bytes,
                    "analysis_incomplete": True,
                },
            )
            if analyze_executable_content and tmp_path is not None:
                executable_probe_outcome = _probe_python_archive_member_executable_content(tmp_path)
                if executable_probe_outcome == "detected":
                    _add_executable_archive_member_check(
                        archive_kind=archive_kind,
                        archive_path=archive_path,
                        member_name=member_name,
                        result=result,
                    )
                elif executable_probe_outcome == "incomplete":
                    _add_incomplete_executable_archive_member_check(
                        archive_kind=archive_kind,
                        archive_path=archive_path,
                        member_name=member_name,
                        result=result,
                        incomplete_reason=executable_analysis_incomplete_reason,
                    )
            return

        if tmp_path is None:
            mark_archive_scan_incomplete(result, python_analysis_incomplete_reason)
            result.add_check(
                name=_PYTHON_MEMBER_CHECK_NAME,
                passed=False,
                message=f"Python archive member could not be extracted for bounded security analysis: {member_name}",
                severity=IssueSeverity.INFO,
                location=location,
                details={"entry": member_name, "analysis_incomplete": True},
            )
            return

        try:
            with open(tmp_path, "rb") as member_file:
                source_bytes = member_file.read()
            if analyze_executable_content and _python_member_has_non_python_shebang(source_bytes):
                _add_executable_archive_member_check(
                    archive_kind=archive_kind,
                    archive_path=archive_path,
                    member_name=member_name,
                    result=result,
                )
                return
            calls = high_risk_python_calls_in_source(source_bytes)
        except PythonArchiveMemberParseError as exc:
            if analyze_executable_content:
                executable_probe_outcome = _probe_python_archive_member_executable_content(tmp_path)
                if executable_probe_outcome == "detected":
                    _add_executable_archive_member_check(
                        archive_kind=archive_kind,
                        archive_path=archive_path,
                        member_name=member_name,
                        result=result,
                    )
                    return
                if executable_probe_outcome == "incomplete":
                    _add_incomplete_executable_archive_member_check(
                        archive_kind=archive_kind,
                        archive_path=archive_path,
                        member_name=member_name,
                        result=result,
                        incomplete_reason=executable_analysis_incomplete_reason,
                    )
                    return

            mark_archive_scan_incomplete(result, python_analysis_incomplete_reason)
            result.add_check(
                name=_PYTHON_MEMBER_CHECK_NAME,
                passed=False,
                message=f"Python archive member could not be parsed for bounded security analysis: {member_name}",
                severity=IssueSeverity.INFO,
                location=location,
                details={
                    "entry": member_name,
                    "exception": str(exc),
                    "exception_type": type(exc).__name__,
                    "analysis_incomplete": True,
                },
            )
            return

        _add_python_archive_member_call_checks(
            archive_kind=archive_kind,
            archive_path=archive_path,
            member_name=member_name,
            result=result,
            calls=calls,
        )
        return

    if (
        analyze_python_source
        and (sniff_python_source or "." not in normalized_lower.rsplit("/", maxsplit=1)[-1])
        and total_size <= max_python_analysis_bytes
        and tmp_path is not None
    ):
        try:
            with open(tmp_path, "rb") as member_file:
                calls = high_risk_python_calls_in_source(member_file.read())
        except (OSError, PythonArchiveMemberParseError):
            calls = set()
        if _add_python_archive_member_call_checks(
            archive_kind=archive_kind,
            archive_path=archive_path,
            member_name=member_name,
            result=result,
            calls=calls,
        ):
            return

    if is_executable_archive_member_name(normalized_lower):
        _add_executable_archive_member_check(
            archive_kind=archive_kind,
            archive_path=archive_path,
            member_name=member_name,
            result=result,
        )
        return

    if tmp_path is None or not analyze_executable_content:
        return

    executable_probe_outcome = probe_executable_archive_member_content(tmp_path)
    if executable_probe_outcome == "detected":
        _add_executable_archive_member_check(
            archive_kind=archive_kind,
            archive_path=archive_path,
            member_name=member_name,
            result=result,
        )
    elif executable_probe_outcome == "incomplete":
        _add_incomplete_executable_archive_member_check(
            archive_kind=archive_kind,
            archive_path=archive_path,
            member_name=member_name,
            result=result,
            incomplete_reason=executable_analysis_incomplete_reason,
        )
