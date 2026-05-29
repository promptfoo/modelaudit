"""Shared security helpers for archive member names and source analysis."""

from __future__ import annotations

import ast
import re
import shlex
from collections.abc import Callable, Iterator
from dataclasses import dataclass
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
        name in _STATIC_OVERWRITABLE_HIGH_RISK_REFERENCES
        or _webbrowser_controller_launch_call_name(name) is not None
        or _ctypes_loader_attribute_load_name(name) is not None
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
    return frozenset(
        f"builtins{name.removeprefix('__builtins__')}"
        if name == "__builtins__" or name.startswith("__builtins__.")
        else name
        for name in names
    )


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

    if normalized_helper_names & {"object.__getattribute__", "builtins.object.__getattribute__"}:
        if len(node.args) != 2 or node.keywords:
            return None
        resolved_target_roots = _resolve_static_reference_names(
            node.args[0],
            alias_scopes,
            allow_module_locals_mapping=allow_module_locals_mapping,
            allow_local_namespace_mapping=allow_local_namespace_mapping,
        )
        attr_name = _resolve_static_string(node.args[1])
        if resolved_target_roots is None:
            return None
        if attr_name in {"__getitem__", "LoadLibrary"}:
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
        if len(node.args) != 1 or node.keywords:
            return None
        attr_name = _resolve_static_string(node.args[0])
        if attr_name is None and not getattr_accessor_names:
            return None
        resolved_names: set[str] = set(_ctypes_loader_member_load_names(getattr_accessor_names, attr_name))
        if attr_name is None:
            return frozenset(resolved_names) or None
        getattribute_names = _apply_aliases_to_names(
            frozenset(f"{target_root}.{attr_name}" for target_root in getattribute_accessor_names),
            alias_scopes,
        )
        if getattribute_names is not None:
            resolved_names.update(getattribute_names)
        return frozenset(resolved_names) or None

    has_getattr_helper = bool(normalized_helper_names & {"getattr", "builtins.getattr"})
    has_hasattr_helper = bool(normalized_helper_names & {"hasattr", "builtins.hasattr"})
    if not (has_getattr_helper or has_hasattr_helper):
        return None

    expected_arg_counts = {2, 3} if has_getattr_helper else {2}
    if len(node.args) not in expected_arg_counts or node.keywords:
        return None
    target_root_node = node.args[0]
    attr_name_node = node.args[1]

    attr_name = _resolve_static_string(attr_name_node)
    resolved_target_roots = _resolve_static_reference_names(
        target_root_node,
        alias_scopes,
        allow_module_locals_mapping=allow_module_locals_mapping,
        allow_local_namespace_mapping=allow_local_namespace_mapping,
    )
    if resolved_target_roots is None:
        return None
    if attr_name is None:
        return _ctypes_loader_member_load_names(resolved_target_roots, attr_name) or None
    return _apply_aliases_to_names(
        frozenset(f"{resolved_target_root}.{attr_name}" for resolved_target_root in resolved_target_roots),
        alias_scopes,
    )


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

    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
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
_NAMESPACE_MUTATION_METHODS = _NAMESPACE_WRITE_METHODS | frozenset({"pop"})
_NAMESPACE_MUTATION_DESCRIPTORS = frozenset(
    f"{prefix}.{method}" for prefix in ("dict", "builtins.dict") for method in _NAMESPACE_MUTATION_METHODS
)
_NAMESPACE_MAPPING_METHODS = _NAMESPACE_LOOKUP_METHODS | _NAMESPACE_WRITE_METHODS


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
        if resolved_root in _TRACKED_MODULE_NAMESPACE_ALIASES:
            namespace_names, guaranteed = _resolve_module_namespace_key_names(
                key, alias_scopes, allow_module_locals_mapping=allow_module_locals_mapping
            )
            if namespace_names is not None:
                selected_names.update(namespace_names)
            selected_value_guaranteed = selected_value_guaranteed and guaranteed
            continue
        if resolved_root == _LOCAL_NAMESPACE_MAPPING_ALIAS:
            namespace_names, guaranteed = _resolve_local_namespace_key_names(key, alias_scopes)
            if namespace_names is not None:
                selected_names.update(namespace_names)
            selected_value_guaranteed = selected_value_guaranteed and guaranteed
            continue
        member_name = f"{resolved_root}.{key}"
        member_names, member_is_bound = _lookup_bound_alias(member_name, alias_scopes)
        if not member_is_bound:
            member_names = frozenset({member_name})
        if member_names is not None:
            selected_names.update(member_names)
        selected_value_guaranteed = selected_value_guaranteed and member_is_bound
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
        if len(node.args) == 1 and not node.keywords:
            loader_type_node = node.args[0]
        elif not node.args and len(node.keywords) == 1 and node.keywords[0].arg == "dlltype":
            loader_type_node = node.keywords[0].value
        else:
            loader_type_node = None
        if loader_type_node is not None:
            resolved_loader_types = _resolve_static_reference_names(
                loader_type_node,
                alias_scopes,
                allow_module_locals_mapping=allow_module_locals_mapping,
                allow_local_namespace_mapping=allow_local_namespace_mapping,
            )
            if _canonical_ctypes_loader_type_aliases(resolved_loader_types):
                loader_roots.add(_CTYPES_LIBRARY_LOADER_INSTANCE_ROOT)
    library_name_node: ast.AST | None = None
    if len(node.args) == 1 and not node.keywords:
        library_name_node = node.args[0]
    elif not node.args and len(node.keywords) == 1 and node.keywords[0].arg == "name":
        library_name_node = node.keywords[0].value
    if library_name_node is not None:
        library_name = _resolve_static_string(library_name_node)
        for resolved_func_name in resolved_func_names:
            split_reference = _split_ctypes_loader_reference(resolved_func_name)
            if split_reference is None:
                continue
            root_name, suffix = split_reference
            if suffix in {"__getitem__", "LoadLibrary"}:
                loader_roots.add(f"{root_name}.{library_name or _CTYPES_DYNAMIC_LIBRARY_NAME}")
    for resolved_func_name in resolved_func_names:
        stripped_func_name = _strip_dunder_call_suffixes(resolved_func_name)
        root_name, separator, method_name = stripped_func_name.rpartition(".")
        if not separator or root_name not in _CTYPES_LIBRARY_LOADER_CONSTRUCTORS:
            continue
        if method_name not in {"__getitem__", "LoadLibrary"}:
            continue
        self_node: ast.AST | None = None
        unbound_library_name_node: ast.AST | None = None
        invalid_unbound_call = len(node.args) > 2
        if len(node.args) >= 1:
            self_node = node.args[0]
        if len(node.args) >= 2:
            unbound_library_name_node = node.args[1]
        for keyword in node.keywords:
            if keyword.arg == "self" and self_node is None:
                self_node = keyword.value
            elif keyword.arg == "name" and unbound_library_name_node is None:
                unbound_library_name_node = keyword.value
            else:
                invalid_unbound_call = True
        if invalid_unbound_call or self_node is None or unbound_library_name_node is None:
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


def _resolve_static_reference_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    allow_module_locals_mapping: bool = False,
    allow_local_namespace_mapping: bool = False,
) -> frozenset[str] | None:
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
        self._class_scope_ids: set[int] = set()
        self._comprehension_outer_scope_indices: list[int] = []
        self._call_result_aliases: dict[int, _AliasValue] = {}
        self._non_module_scope_depth = 0
        self.risky_calls: set[str] = set()

    def _resolve_reference_names(self, node: ast.AST) -> frozenset[str] | None:
        return _resolve_static_reference_names(
            node,
            self.alias_scopes,
            allow_module_locals_mapping=self._non_module_scope_depth == 0,
            allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
        )

    def _bind_imported_static_members(self, local_name: str, import_name: str, *, preserve_existing: bool) -> None:
        prefix = f"{import_name}."
        for reference in _STATIC_OVERWRITABLE_HIGH_RISK_REFERENCES:
            if not reference.startswith(prefix):
                continue
            local_reference = f"{local_name}{reference.removeprefix(import_name)}"
            if preserve_existing and local_reference in self.alias_scopes[-1]:
                continue
            self.alias_scopes[-1][local_reference] = _resolve_aliases(
                reference,
                self.alias_scopes,
            )

    def _shadow_member_bindings(self, scope_index: int, local_name: str) -> None:
        if "." in local_name or local_name.startswith(_MODULE_NAMESPACE_WRITE_PREFIX):
            return
        prefix = f"{local_name}."
        current_scope = self.alias_scopes[scope_index]
        for scope in self.alias_scopes:
            for name in tuple(scope):
                if name.startswith(prefix):
                    current_scope[name] = None

    def _record_import(self, alias: ast.alias, import_name: str) -> None:
        local_name = alias.asname or alias.name
        previous_names, _found = _lookup_bound_alias(local_name, self.alias_scopes)
        preserve_existing = isinstance(previous_names, frozenset) and import_name in previous_names
        self._bind_name(local_name, frozenset({import_name}))
        self._bind_imported_static_members(local_name, import_name, preserve_existing=preserve_existing)

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

    def _should_track_syntactic_static_reference(self, syntactic_name: str) -> bool:
        root_name = syntactic_name.split(".", maxsplit=1)[0]
        root_aliases, found = _lookup_bound_alias(root_name, self.alias_scopes)
        return not found or (isinstance(root_aliases, frozenset) and root_name in root_aliases)

    def _localize_instance_binding_value(
        self, local_name: str, value: ast.AST, resolved_names: _AliasValue
    ) -> _AliasValue:
        if not isinstance(resolved_names, frozenset):
            return resolved_names
        localized_names = set(resolved_names)
        if _CTYPES_LIBRARY_LOADER_INSTANCE_ROOT in localized_names:
            localized_names.remove(_CTYPES_LIBRARY_LOADER_INSTANCE_ROOT)
            localized_names.add(_localized_instance_root(_CTYPES_LIBRARY_LOADER_INSTANCE_ROOT, local_name))
        webbrowser_controller_roots = _resolve_webbrowser_controller_factory_roots(
            value,
            self.alias_scopes,
            allow_module_locals_mapping=self._non_module_scope_depth == 0,
            allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
        )
        for controller_root in webbrowser_controller_roots or frozenset():
            if controller_root in localized_names:
                localized_names.remove(controller_root)
                localized_names.add(_localized_instance_root(controller_root, local_name))
        return frozenset(localized_names)

    def _bind_module_namespace_key(self, key: str, resolved_names: _AliasValue) -> None:
        self._bind_name(f"{_MODULE_NAMESPACE_WRITE_PREFIX}{key}", resolved_names)
        if self._non_module_scope_depth == 0:
            self._bind_name(key, resolved_names)

    def _resolve_binding_value_names(self, value: ast.AST | None) -> _AliasValue:
        if value is None:
            return None
        if isinstance(value, ast.Call) and id(value) in self._call_result_aliases:
            return self._call_result_aliases[id(value)]
        value_name = _resolve_call_name(value)
        if value_name is not None and _is_high_risk_python_call_name(value_name):
            return frozenset({value_name})
        return self._resolve_reference_names(value)

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
        self.alias_scopes.append(scope if scope is not None else {})

    def _pop_alias_scope(self) -> None:
        self.alias_scopes.pop()

    def _bind_target_to_value(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            resolved_names = self._resolve_binding_value_names(value)
            localized_names = self._localize_instance_binding_value(target.id, value, resolved_names)
            self._restore_reassigned_instance_member_defaults(target.id, localized_names)
            self._bind_name(target.id, localized_names)
        elif isinstance(target, ast.Subscript):
            key = _resolve_static_string(target.slice)
            roots = _resolve_namespace_mapping_roots(
                target.value,
                self.alias_scopes,
                allow_module_locals_mapping=self._non_module_scope_depth == 0,
                allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
            )
            if key is not None and roots is not None:
                resolved_value = self._resolve_binding_value_names(value)
                for root in roots:
                    if root in _TRACKED_MODULE_NAMESPACE_ALIASES:
                        self._bind_module_namespace_key(key, resolved_value)
                        continue
                    if root == _LOCAL_NAMESPACE_MAPPING_ALIAS:
                        self._bind_name(key, resolved_value)
                        continue
                    self._bind_name(f"{root}.{key}", resolved_value)
        elif isinstance(target, ast.Attribute):
            syntactic_name, target_names = self._overwritable_target_names(target)
            if not target_names:
                return
            resolved_value = self._resolve_binding_value_names(value)
            for target_name in target_names:
                self._bind_name(target_name, resolved_value)
            if syntactic_name is not None:
                self._bind_name(syntactic_name, resolved_value)
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
                for name in _binding_names(target):
                    self._bind_name(name, None)

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

    def _restore_deleted_overwritable_target(self, target: ast.AST) -> None:
        if not isinstance(target, ast.Attribute):
            return
        syntactic_name, target_names = self._overwritable_target_names(target)
        if not target_names:
            return
        for target_name in target_names:
            self._bind_name(target_name, frozenset({target_name}))
        if syntactic_name is not None:
            self._bind_name(syntactic_name, target_names)

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
            if method_name == "__setitem__":
                expected_arg_counts = {3} if is_descriptor else {2}
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
                return existing_names
            return self._merge_alias_values(existing_names, default_names)
        if root == _LOCAL_NAMESPACE_MAPPING_ALIAS:
            existing_names, guaranteed = _resolve_local_namespace_key_names(key, self.alias_scopes)
            if guaranteed:
                return existing_names
            return self._merge_alias_values(default_names)

        member_name = f"{root}.{key}"
        existing_names, guaranteed = _lookup_bound_alias(member_name, self.alias_scopes)
        if guaranteed:
            return existing_names
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
        dotted_name = f"{root}.{key}"
        for scope in self.alias_scopes:
            scope.pop(dotted_name, None)

    def _record_namespace_write_call(self, node: ast.Call) -> None:
        write_call = self._resolve_namespace_write_call(node)
        if write_call is None:
            return

        method_name, roots, key, value_node = write_call
        if method_name == "pop":
            for root in roots:
                self._delete_namespace_key(root, key)
            return

        value_names = self._resolve_binding_value_names(value_node) if value_node is not None else None
        for root in roots:
            resolved_value = (
                self._setdefault_value_for_key(root, key, value_names) if method_name == "setdefault" else value_names
            )
            if root in _TRACKED_MODULE_NAMESPACE_ALIASES:
                self._bind_module_namespace_key(key, resolved_value)
                continue
            if root == _LOCAL_NAMESPACE_MAPPING_ALIAS:
                self._bind_name(key, resolved_value)
                continue
            self._bind_name(f"{root}.{key}", resolved_value)

    def _record_setattr_call(self, node: ast.Call) -> None:
        helper_name = _resolve_call_name(node.func)
        resolved_helper_names = _apply_aliases(helper_name, self.alias_scopes) if helper_name is not None else None
        if not resolved_helper_names or not (resolved_helper_names & {"setattr", "builtins.setattr"}):
            return
        if len(node.args) != 3 or node.keywords:
            return
        attr_name = _resolve_static_string(node.args[1])
        if attr_name is None:
            return
        target_roots = self._resolve_reference_names(node.args[0])
        if target_roots is None:
            return
        resolved_value = self._resolve_binding_value_names(node.args[2])
        for target_root in target_roots:
            target_name = f"{target_root}.{attr_name}"
            if _is_overwritable_high_risk_reference(target_name):
                self._bind_name(target_name, resolved_value)

    def _shadow_binding_target(self, target: ast.AST) -> None:
        for name in _binding_names(target):
            self._bind_name(name, None)

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
        candidate_bindings = [self._resolve_target_bindings(target, element) for element in iterable.elts]
        for name in _binding_names(target):
            resolved_names = frozenset(
                alias for bindings in candidate_bindings for alias in (bindings.get(name) or frozenset())
            )
            self._bind_name(name, resolved_names or None)

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
        for alias in node.names:
            if alias.name == "*":
                for local_name, import_name in _wildcard_import_aliases(node.module):
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

    @staticmethod
    def _constant_bool(node: ast.AST) -> bool | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return node.value
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
            if name.startswith(_MODULE_NAMESPACE_WRITE_PREFIX):
                key = name.removeprefix(_MODULE_NAMESPACE_WRITE_PREFIX)
                base_value, _guaranteed = _resolve_module_namespace_key_names(
                    key,
                    self.alias_scopes,
                    allow_module_locals_mapping=self._non_module_scope_depth == 0,
                )
            else:
                high_risk_default = self._conditionally_overwritable_high_risk_reference_default(name)
                if high_risk_default is not None:
                    base_value = current_scope.get(name, high_risk_default)
                else:
                    base_value = current_scope.get(name, frozenset({name}) if implicit_builtins else None)
            values = [scope.get(name, base_value) for scope in branch_scopes]
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

    def _visit_class_scope(self, body: list[ast.stmt]) -> None:
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

    def _visit_function_scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
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

    def _class_local_alias_scope(self, node: ast.ClassDef) -> _AliasScope:
        class_scope: _AliasScope = {}
        self._push_alias_scope(class_scope)
        self._class_scope_ids.add(id(class_scope))
        try:
            for statement in node.body:
                if isinstance(statement, ast.Assign):
                    resolved_value = self._resolve_binding_value_names(statement.value)
                    for target in statement.targets:
                        for name in _binding_names(target):
                            class_scope[name] = resolved_value
                elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
                    resolved_value = self._resolve_binding_value_names(statement.value)
                    for name in _binding_names(statement.target):
                        class_scope[name] = resolved_value
                elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    class_scope[statement.name] = None
        finally:
            self._class_scope_ids.discard(id(class_scope))
            self._pop_alias_scope()
        return class_scope

    @staticmethod
    def _class_local_method_aliases(func: ast.AST, class_scope: _AliasScope) -> frozenset[str]:
        if not (
            isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in {"self", "cls"}
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

    @staticmethod
    def _argument_alias_scope(arguments: ast.arguments) -> _AliasScope:
        argument_names = [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        ]
        scope: _AliasScope = {argument.arg: None for argument in argument_names}
        if arguments.vararg is not None:
            scope[arguments.vararg.arg] = None
        if arguments.kwarg is not None:
            scope[arguments.kwarg.arg] = None
        return scope

    def _resolve_initializer_reference_names(
        self,
        node: ast.AST,
        class_scope: _AliasScope,
        initializer_scope: _AliasScope,
    ) -> frozenset[str] | None:
        class_local_names = self._class_local_method_aliases(node, class_scope)
        if class_local_names:
            return class_local_names
        return _resolve_static_reference_names(
            node,
            [*self.alias_scopes, initializer_scope],
            allow_module_locals_mapping=self._non_module_scope_depth == 0,
            allow_local_namespace_mapping=bool(self._comprehension_outer_scope_indices),
        )

    def _initializer_call_preserves_ctypes_loader_init(
        self,
        call: ast.Call,
        class_scope: _AliasScope,
        initializer_scope: _AliasScope,
        first_base_loader_types: frozenset[str],
    ) -> bool:
        if (
            first_base_loader_types
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "__init__"
            and isinstance(call.func.value, ast.Call)
            and _resolve_call_name(call.func.value.func) == "super"
        ):
            return True
        return self._is_ctypes_loader_init_alias(
            self._resolve_initializer_reference_names(call.func, class_scope, initializer_scope)
        )

    def _initializer_node_preserves_ctypes_loader_init(
        self,
        node: ast.AST,
        class_scope: _AliasScope,
        initializer_scope: _AliasScope,
        first_base_loader_types: frozenset[str],
    ) -> bool:
        return any(
            self._initializer_call_preserves_ctypes_loader_init(
                call,
                class_scope,
                initializer_scope,
                first_base_loader_types,
            )
            for call in self._initializer_node_calls(node)
        )

    def _merge_initializer_branch_scopes(
        self,
        initializer_scope: _AliasScope,
        branch_scopes: list[_AliasScope],
    ) -> None:
        base_scope = dict(initializer_scope)
        for name in {name for scope in branch_scopes for name in scope}:
            initializer_scope[name] = self._merge_alias_values(
                *(scope.get(name, base_scope.get(name)) for scope in branch_scopes)
            )

    def _initializer_statements_preserve_ctypes_loader_init(
        self,
        statements: list[ast.stmt],
        class_scope: _AliasScope,
        initializer_scope: _AliasScope,
        first_base_loader_types: frozenset[str],
    ) -> bool:
        for statement in statements:
            if self._initializer_statement_preserves_ctypes_loader_init(
                statement,
                class_scope,
                initializer_scope,
                first_base_loader_types,
            ):
                return True
        return False

    def _initializer_statement_preserves_ctypes_loader_init(
        self,
        statement: ast.stmt,
        class_scope: _AliasScope,
        initializer_scope: _AliasScope,
        first_base_loader_types: frozenset[str],
    ) -> bool:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return False
        if isinstance(statement, ast.If):
            constant_bool = self._constant_bool(statement.test)
            if constant_bool is True:
                return self._initializer_statements_preserve_ctypes_loader_init(
                    statement.body,
                    class_scope,
                    initializer_scope,
                    first_base_loader_types,
                )
            if constant_bool is False:
                return self._initializer_statements_preserve_ctypes_loader_init(
                    statement.orelse,
                    class_scope,
                    initializer_scope,
                    first_base_loader_types,
                )
            branch_scopes = [dict(initializer_scope), dict(initializer_scope)]
            if self._initializer_statements_preserve_ctypes_loader_init(
                statement.body,
                class_scope,
                branch_scopes[0],
                first_base_loader_types,
            ):
                return True
            if self._initializer_statements_preserve_ctypes_loader_init(
                statement.orelse,
                class_scope,
                branch_scopes[1],
                first_base_loader_types,
            ):
                return True
            self._merge_initializer_branch_scopes(initializer_scope, branch_scopes)
            return False
        if isinstance(statement, ast.While):
            constant_bool = self._constant_bool(statement.test)
            if constant_bool is False:
                return self._initializer_statements_preserve_ctypes_loader_init(
                    statement.orelse,
                    class_scope,
                    initializer_scope,
                    first_base_loader_types,
                )
            branch_scope = dict(initializer_scope)
            if self._initializer_statements_preserve_ctypes_loader_init(
                statement.body,
                class_scope,
                branch_scope,
                first_base_loader_types,
            ):
                return True
            self._merge_initializer_branch_scopes(initializer_scope, [branch_scope, dict(initializer_scope)])
            return False
        if isinstance(statement, ast.Assign):
            if self._initializer_node_preserves_ctypes_loader_init(
                statement.value,
                class_scope,
                initializer_scope,
                first_base_loader_types,
            ):
                return True
            resolved_value = self._resolve_initializer_reference_names(statement.value, class_scope, initializer_scope)
            for target in statement.targets:
                for name in _binding_names(target):
                    initializer_scope[name] = resolved_value
            return False
        if isinstance(statement, ast.AnnAssign):
            if statement.value is None:
                for name in _binding_names(statement.target):
                    initializer_scope[name] = None
                return False
            if self._initializer_node_preserves_ctypes_loader_init(
                statement.value,
                class_scope,
                initializer_scope,
                first_base_loader_types,
            ):
                return True
            resolved_value = self._resolve_initializer_reference_names(statement.value, class_scope, initializer_scope)
            for name in _binding_names(statement.target):
                initializer_scope[name] = resolved_value
            return False
        return self._initializer_node_preserves_ctypes_loader_init(
            statement,
            class_scope,
            initializer_scope,
            first_base_loader_types,
        )

    def _class_preserves_ctypes_loader_init(self, node: ast.ClassDef, class_scope: _AliasScope) -> bool:
        init_method = next(
            (
                statement
                for statement in node.body
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name == "__init__"
            ),
            None,
        )
        if init_method is None:
            if not node.bases:
                return False
            return bool(_canonical_ctypes_loader_type_aliases(self._resolve_reference_names(node.bases[0])))
        first_base_loader_types = (
            _canonical_ctypes_loader_type_aliases(self._resolve_reference_names(node.bases[0]))
            if node.bases
            else frozenset()
        )
        initializer_scope = self._argument_alias_scope(init_method.args)
        return self._initializer_statements_preserve_ctypes_loader_init(
            init_method.body,
            class_scope,
            initializer_scope,
            first_base_loader_types,
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        ctypes_loader_type_aliases = (
            frozenset(
                alias
                for base in node.bases
                for alias in _canonical_ctypes_loader_type_aliases(self._resolve_reference_names(base))
            )
            if self._class_preserves_ctypes_loader_init(node, self._class_local_alias_scope(node))
            else frozenset()
        )
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword)
        self._visit_class_scope(node.body)
        self._bind_name(node.name, ctypes_loader_type_aliases or None)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        self._push_alias_scope()
        try:
            self._bind_arguments(node.args)
            self._non_module_scope_depth += 1
            try:
                self.visit(node.body)
            finally:
                self._non_module_scope_depth -= 1
        finally:
            self._pop_alias_scope()

    def _visit_comprehension(
        self, generators: list[ast.comprehension], result_nodes: list[ast.AST], *, inline_module_scope: bool
    ) -> None:
        if not generators:
            return
        self.visit(generators[0].iter)
        outer_scope_index = len(self.alias_scopes) - 1
        self._push_alias_scope()
        self._comprehension_outer_scope_indices.append(outer_scope_index)
        has_module_locals = inline_module_scope and self._non_module_scope_depth == 0
        if not has_module_locals:
            self._non_module_scope_depth += 1
        try:
            first_generator, *remaining_generators = generators
            self._bind_comprehension_target(first_generator.target, first_generator.iter)
            self.visit(first_generator.target)
            for condition in first_generator.ifs:
                self.visit(condition)
            for generator in remaining_generators:
                self.visit(generator.iter)
                self._bind_comprehension_target(generator.target, generator.iter)
                self.visit(generator.target)
                for condition in generator.ifs:
                    self.visit(condition)
            for result_node in result_nodes:
                self.visit(result_node)
        finally:
            if not has_module_locals:
                self._non_module_scope_depth -= 1
            self._comprehension_outer_scope_indices.pop()
            self._pop_alias_scope()

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, [node.elt], inline_module_scope=False)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node.generators, [node.elt], inline_module_scope=False)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node.generators, [node.elt], inline_module_scope=False)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node.generators, [node.key, node.value], inline_module_scope=False)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self._bind_target_to_value(target, node.value)
            self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.annotation is not None:
            self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
            self._bind_target_to_value(node.target, node.value)
        else:
            self._shadow_binding_target(node.target)
        self.visit(node.target)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self._restore_deleted_overwritable_target(target)
            self.visit(target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        resolved_names = self._resolve_reference_names(node.target)
        if resolved_names is not None:
            for resolved_name in resolved_names:
                normalized_name = _ctypes_loader_attribute_load_name(resolved_name)
                if normalized_name is not None:
                    self.risky_calls.add(normalized_name)
        self._shadow_binding_target(node.target)
        self.visit(node.target)

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
        iter_truth = self._literal_iter_truth(node.iter)
        if iter_truth is False:
            for statement in node.orelse:
                self.visit(statement)
            return

        body_scope: _AliasScope = {}
        self._push_alias_scope(body_scope)
        try:
            self._shadow_binding_target(node.target)
            self.visit(node.target)
            for statement in node.body:
                self.visit(statement)
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
        self.visit(node.test)
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
        self.visit(node.test)
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
            if item.optional_vars is not None:
                self._shadow_binding_target(item.optional_vars)
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
        call_result_names = self._resolve_reference_names(node)
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
        for resolved_name in resolved_names:
            normalized_name = _normalized_high_risk_python_call_name(resolved_name)
            if normalized_name is not None:
                self.risky_calls.add(normalized_name)
        self._record_namespace_write_call(node)
        self._record_setattr_call(node)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
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
        PythonArchiveMemberParseError: when the source cannot be parsed.
    """
    try:
        tree = ast.parse(source_bytes)
    except (SyntaxError, ValueError) as exc:
        raise PythonArchiveMemberParseError(str(exc)) from exc

    return high_risk_python_calls_in_tree(tree)


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
        and "." not in normalized_lower.rsplit("/", maxsplit=1)[-1]
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
