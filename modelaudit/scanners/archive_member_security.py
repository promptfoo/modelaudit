"""Shared security helpers for archive member names and source analysis."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from ._archive_outcomes import mark_archive_scan_incomplete
from .base import IssueSeverity

if TYPE_CHECKING:
    from .base import ScanResult

_EXECUTABLE_ARCHIVE_MEMBER_SUFFIXES = (
    ".sh",
    ".bash",
    ".cmd",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".scr",
    ".com",
    ".bat",
    ".ps1",
)
_EXECUTABLE_ARCHIVE_MEMBER_SUFFIX_RULE_CODES = (
    ((".exe", ".dll", ".scr", ".com"), "S501"),
    ((".so",), "S502"),
    ((".dylib",), "S503"),
    ((".sh", ".bash"), "S504"),
    ((".cmd", ".bat"), "S505"),
    ((".ps1",), "S506"),
)
_EXECUTABLE_ARCHIVE_MEMBER_MAGIC_READ_BYTES = 1024
_PORTABLE_EXECUTABLE_POINTER_OFFSET = 0x3C
_PORTABLE_EXECUTABLE_MIN_HEADER_OFFSET = 0x40
_PORTABLE_EXECUTABLE_MAX_HEADER_OFFSET = 1024 * 1024
_PORTABLE_EXECUTABLE_SIGNATURE = b"PE\x00\x00"
_EXECUTABLE_ARCHIVE_MEMBER_MAGIC_RULE_CODES = (
    ((b"\x7fELF",), "S502"),
    ((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"), "S503"),
    ((b"#!",), "S504"),
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
_HIGH_RISK_PYTHON_CALLS = {
    "__import__",
    "__builtin__.__import__",
    "__builtin__.eval",
    "__builtin__.exec",
    "__builtins__.__import__",
    "__builtins__.eval",
    "__builtins__.exec",
    "builtins.__import__",
    "builtins.eval",
    "builtins.exec",
    "eval",
    "exec",
    "importlib.import_module",
    "os.popen",
    "os.system",
    "pickle.load",
    "pickle.loads",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
}

# Map each high-risk call name to the rule code that best describes its risk
# category. SARIF consumers, dashboards, and per-rule severity overrides rely
# on accurate codes, so `os.system` must not be reported under `S104`
# (eval/exec) just because the scanner hard-coded a single fallback.
_HIGH_RISK_PYTHON_CALL_RULE_CODES: dict[str, str] = {
    "__import__": "S106",
    "__builtin__.__import__": "S106",
    "__builtins__.__import__": "S106",
    "builtins.__import__": "S106",
    "__builtin__.eval": "S104",
    "__builtin__.exec": "S104",
    "__builtins__.eval": "S104",
    "__builtins__.exec": "S104",
    "builtins.eval": "S104",
    "builtins.exec": "S104",
    "eval": "S104",
    "exec": "S104",
    "importlib.import_module": "S107",
    "os.popen": "S101",
    "os.system": "S101",
    "pickle.load": "S213",
    "pickle.loads": "S213",
}
_HIGH_RISK_PYTHON_CALL_PREFIX_RULE_CODES: tuple[tuple[str, str], ...] = (("subprocess.", "S103"),)
_FALLBACK_HIGH_RISK_RULE_CODE = "S104"


def _rule_code_for_high_risk_call(call_name: str) -> str:
    """Return the rule code that most accurately describes ``call_name``."""
    direct = _HIGH_RISK_PYTHON_CALL_RULE_CODES.get(call_name)
    if direct is not None:
        return direct
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
_MISSING_ALIAS = object()


def is_executable_archive_member_name(member_name: str) -> bool:
    """Return True when an archive member name has an executable/native-library suffix."""
    normalized_name = member_name.lower()
    return normalized_name.endswith(_EXECUTABLE_ARCHIVE_MEMBER_SUFFIXES) or bool(
        _VERSIONED_SHARED_OBJECT_SUFFIX_RE.search(normalized_name)
    )


def executable_archive_member_rule_code(member_name: str, *, path: str | None = None) -> str | None:
    """Return the rule code for an executable archive member name or content probe."""
    normalized_name = member_name.lower()
    for suffixes, rule_code in _EXECUTABLE_ARCHIVE_MEMBER_SUFFIX_RULE_CODES:
        if normalized_name.endswith(suffixes):
            return rule_code
    if _VERSIONED_SHARED_OBJECT_SUFFIX_RE.search(normalized_name):
        return "S502"
    if path is not None:
        return _executable_archive_member_content_rule_code(path)
    return None


def _looks_like_portable_executable(prefix: bytes, *, path: str) -> bool:
    if not prefix.startswith(b"MZ"):
        return False
    if b"This program cannot be run in DOS mode" in prefix[:512]:
        return True
    if len(prefix) < _PORTABLE_EXECUTABLE_MIN_HEADER_OFFSET:
        return False

    pe_offset = int.from_bytes(
        prefix[_PORTABLE_EXECUTABLE_POINTER_OFFSET : _PORTABLE_EXECUTABLE_POINTER_OFFSET + 4],
        "little",
        signed=False,
    )
    if not _PORTABLE_EXECUTABLE_MIN_HEADER_OFFSET <= pe_offset <= _PORTABLE_EXECUTABLE_MAX_HEADER_OFFSET:
        return False

    if pe_offset + len(_PORTABLE_EXECUTABLE_SIGNATURE) <= len(prefix):
        return prefix[pe_offset : pe_offset + len(_PORTABLE_EXECUTABLE_SIGNATURE)] == _PORTABLE_EXECUTABLE_SIGNATURE

    try:
        with open(path, "rb") as member_file:
            member_file.seek(pe_offset)
            return member_file.read(len(_PORTABLE_EXECUTABLE_SIGNATURE)) == _PORTABLE_EXECUTABLE_SIGNATURE
    except OSError:
        return False


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


def _executable_archive_member_content_rule_code(path: str) -> str | None:
    """Return the rule code for a bounded executable-content signature probe."""
    try:
        with open(path, "rb") as member_file:
            prefix = member_file.read(_EXECUTABLE_ARCHIVE_MEMBER_MAGIC_READ_BYTES)
    except OSError:
        return None

    for prefixes, rule_code in _EXECUTABLE_ARCHIVE_MEMBER_MAGIC_RULE_CODES:
        if prefix.startswith(prefixes):
            return rule_code
    if _looks_like_macho_fat_binary(prefix):
        return "S503"
    if _looks_like_portable_executable(prefix, path=path):
        return "S501"
    return None


def is_executable_archive_member_content(path: str) -> bool:
    """Return True when a member begins with a strong executable signature."""
    return _executable_archive_member_content_rule_code(path) is not None


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


def _resolve_aliases(name: str, alias_scopes: _AliasScopes) -> _AliasValue:
    for aliases in reversed(alias_scopes):
        if name in aliases:
            return aliases[name]
    return frozenset({name})


def _apply_aliases(call_name: str, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    head, *tail = call_name.split(".")
    resolved_heads = _resolve_aliases(head, alias_scopes)
    if resolved_heads is None:
        return None
    if not tail:
        return resolved_heads
    suffix = ".".join(tail)
    return frozenset(f"{resolved_head}.{suffix}" for resolved_head in resolved_heads)


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


_NAMESPACE_MAPPING_ACCESSORS = {"get", "__getitem__", "pop", "setdefault"}
_GLOBAL_NAMESPACE_HELPERS = {"globals", "builtins.globals"}
_GLOBAL_NAMESPACE_MAPPING_MARKER = "<globals mapping>"
_STATIC_REFERENCE_OVERRIDE_PREFIX = "<static reference override>:"
_STATIC_MAPPING_MUTATION_ALIAS_PREFIX = "<static mapping mutation alias>:"
_STATIC_UNCERTAIN_BINDING_PREFIX = "<uncertain static binding>:"
_CAPTURED_CALLABLE_REFERENCE_PREFIX = "<captured callable>:"
_BUILTIN_NAMESPACE_NAMES = {"__builtin__", "__builtins__"}
_STATIC_MAPPING_MUTATORS = {"__delitem__", "__setitem__", "pop", "update"}
_STATIC_ATTRIBUTE_MUTATION_HELPERS = {
    "setattr",
    "__builtin__.setattr",
    "__builtins__.setattr",
    "builtins.setattr",
}
_STATIC_MAPPING_FUNCTION_MUTATORS = {
    "dict.__setitem__": "__setitem__",
    "builtins.dict.__setitem__": "__setitem__",
    "dict.__delitem__": "__delitem__",
    "builtins.dict.__delitem__": "__delitem__",
    "dict.update": "update",
    "builtins.dict.update": "update",
    "dict.pop": "pop",
    "builtins.dict.pop": "pop",
    "operator.delitem": "__delitem__",
    "operator.setitem": "__setitem__",
}


def _has_uncertain_static_binding(node: ast.AST, alias_scopes: _AliasScopes) -> bool:
    """Return whether ``node`` uses a name whose identity diverged across branches."""
    for child in ast.walk(node):
        if not isinstance(child, ast.Name):
            continue
        uncertainty_key = f"{_STATIC_UNCERTAIN_BINDING_PREFIX}{child.id}"
        for aliases in reversed(alias_scopes):
            if uncertainty_key in aliases:
                if aliases[uncertainty_key] is None:
                    return True
                break
    return False


def _resolve_global_namespace_mappings(node: ast.AST, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    """Resolve the mapping returned by an unshadowed zero-argument ``globals()`` call."""
    if isinstance(node, ast.Call) and not node.args and not node.keywords:
        helper_name = _resolve_call_name(node.func)
        resolved_helper_names = _apply_aliases(helper_name, alias_scopes) if helper_name is not None else None
        if resolved_helper_names is not None and resolved_helper_names & _GLOBAL_NAMESPACE_HELPERS:
            return frozenset({_GLOBAL_NAMESPACE_MAPPING_MARKER})

    namespace_name = _resolve_call_name(node)
    resolved_namespace_names = _apply_aliases(namespace_name, alias_scopes) if namespace_name is not None else None
    if resolved_namespace_names is not None and _GLOBAL_NAMESPACE_MAPPING_MARKER in resolved_namespace_names:
        return frozenset({_GLOBAL_NAMESPACE_MAPPING_MARKER})
    return None


def _resolve_aliased_mapping_accessor_roots(node: ast.AST, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    """Resolve receivers for a statically aliased mapping accessor invocation."""
    if not isinstance(node, ast.Call) or not node.args:
        return None

    helper_name = _resolve_call_name(node.func)
    resolved_helper_names = _apply_aliases(helper_name, alias_scopes) if helper_name is not None else None
    if resolved_helper_names is None:
        return None

    roots = {
        helper_name.rsplit(".", maxsplit=1)[0]
        for helper_name in resolved_helper_names
        if "." in helper_name and helper_name.rsplit(".", maxsplit=1)[1] in _NAMESPACE_MAPPING_ACCESSORS
    }
    return frozenset(roots) if roots else None


def _resolve_global_builtin_namespace_roots(node: ast.AST, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    """Resolve a statically addressed builtin namespace obtained from ``globals()``."""
    namespace_node: ast.AST | None
    attr_name_node: ast.AST
    if isinstance(node, ast.Subscript):
        namespace_node = node.value
        attr_name_node = node.slice
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _NAMESPACE_MAPPING_ACCESSORS
        and node.args
    ):
        namespace_node = node.func.value
        attr_name_node = node.args[0]
    elif isinstance(node, ast.Call) and node.args:
        accessor_roots = _resolve_aliased_mapping_accessor_roots(node, alias_scopes)
        if accessor_roots is None or _GLOBAL_NAMESPACE_MAPPING_MARKER not in accessor_roots:
            return None
        namespace_node = None
        attr_name_node = node.args[0]
    else:
        return None

    attr_name = _resolve_static_string(attr_name_node)
    if attr_name not in _BUILTIN_NAMESPACE_NAMES:
        return None
    if namespace_node is not None and _resolve_global_namespace_mappings(namespace_node, alias_scopes) is None:
        return None
    return frozenset({attr_name})


def _resolve_direct_global_builtin_namespace_roots(node: ast.AST, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    """Resolve builtin mappings fetched directly from an unshadowed ``globals()`` call."""
    namespace_node: ast.AST
    attr_name_node: ast.AST
    if isinstance(node, ast.Subscript):
        namespace_node = node.value
        attr_name_node = node.slice
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _NAMESPACE_MAPPING_ACCESSORS
        and node.args
    ):
        namespace_node = node.func.value
        attr_name_node = node.args[0]
    else:
        return None

    if (
        not isinstance(namespace_node, ast.Call)
        or namespace_node.args
        or namespace_node.keywords
        or not isinstance(namespace_node.func, ast.Name)
        or namespace_node.func.id != "globals"
        or any("globals" in aliases for aliases in alias_scopes)
    ):
        return None
    attr_name = _resolve_static_string(attr_name_node)
    if attr_name not in _BUILTIN_NAMESPACE_NAMES:
        return None
    return frozenset({attr_name})


def _resolve_certain_namespace_mutation_roots(node: ast.AST, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    """Resolve namespace mappings whose mutation target is statically certain."""
    direct_builtin_roots = _resolve_direct_global_builtin_namespace_roots(node, alias_scopes)
    if direct_builtin_roots is not None:
        return direct_builtin_roots

    if _has_uncertain_static_binding(node, alias_scopes):
        return None

    target_roots = _resolve_namespace_dict_roots(node, alias_scopes)
    return target_roots if target_roots is not None and len(target_roots) == 1 else None


def _resolve_static_mapping_mutator_names(node: ast.AST, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    """Resolve mutation methods bound from one certain namespace mapping."""
    if not isinstance(node, ast.Attribute) or node.attr not in _STATIC_MAPPING_MUTATORS:
        return None

    target_roots = _resolve_certain_namespace_mutation_roots(node.value, alias_scopes)
    if target_roots is None:
        return None
    return frozenset(f"{target_root}.{node.attr}" for target_root in target_roots)


def _resolve_static_attribute_names(
    target_root_node: ast.AST, attr_name_node: ast.AST, alias_scopes: _AliasScopes
) -> frozenset[str] | None:
    attr_name = _resolve_static_string(attr_name_node)
    if attr_name is None:
        return None

    resolved_target_roots = _resolve_global_builtin_namespace_roots(target_root_node, alias_scopes)
    if resolved_target_roots is None:
        target_root = _resolve_call_name(target_root_node)
        if target_root is None:
            return None
        resolved_target_roots = _apply_aliases(target_root, alias_scopes)
    if resolved_target_roots is None:
        return None
    return frozenset(f"{resolved_target_root}.{attr_name}" for resolved_target_root in resolved_target_roots)


def _resolve_getattr_call_names(node: ast.AST, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    # Resolve literal names and compile-time string concatenation. Runtime-built
    # names still fall outside this static member analysis by design.
    if isinstance(node, ast.Attribute) and node.attr == "__call__":
        return _resolve_getattr_call_names(node.value, alias_scopes)

    if not isinstance(node, ast.Call):
        return None

    helper_name = _resolve_call_name(node.func)
    if helper_name is None:
        return None

    resolved_helper_names = _apply_aliases(helper_name, alias_scopes)
    if resolved_helper_names is None or not (resolved_helper_names & {"getattr", "builtins.getattr"}):
        return None

    target_root_node: ast.AST | None = node.args[0] if node.args else None
    attr_name_node: ast.AST | None = node.args[1] if len(node.args) >= 2 else None
    for keyword in node.keywords:
        if keyword.arg == "object" and target_root_node is None:
            target_root_node = keyword.value
        elif keyword.arg == "name" and attr_name_node is None:
            attr_name_node = keyword.value

    if target_root_node is None or attr_name_node is None:
        return None

    return _resolve_static_attribute_names(target_root_node, attr_name_node, alias_scopes)


def _resolve_dunder_getattribute_call_names(node: ast.AST, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    if isinstance(node, ast.Attribute) and node.attr == "__call__":
        return _resolve_dunder_getattribute_call_names(node.value, alias_scopes)

    if not isinstance(node, ast.Call):
        return None

    helper_name = _resolve_call_name(node.func)
    resolved_helper_names = _apply_aliases(helper_name, alias_scopes) if helper_name is not None else None
    if resolved_helper_names is not None and resolved_helper_names & {
        "object.__getattribute__",
        "builtins.object.__getattribute__",
    }:
        if len(node.args) < 2:
            return None
        return _resolve_static_attribute_names(node.args[0], node.args[1], alias_scopes)

    if not isinstance(node.func, ast.Attribute) or node.func.attr != "__getattribute__" or not node.args:
        return None
    return _resolve_static_attribute_names(node.func.value, node.args[0], alias_scopes)


def _resolve_namespace_dict_roots(node: ast.AST, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    global_builtin_roots = _resolve_global_builtin_namespace_roots(node, alias_scopes)
    if global_builtin_roots is not None:
        return global_builtin_roots

    target_root_node: ast.AST | None = None
    namespace_node = node
    if isinstance(namespace_node, ast.Attribute) and namespace_node.attr == "__dict__":
        target_root_node = namespace_node.value
    elif isinstance(namespace_node, ast.Call) and len(namespace_node.args) == 1 and not namespace_node.keywords:
        helper_name = _resolve_call_name(namespace_node.func)
        resolved_helper_names = _apply_aliases(helper_name, alias_scopes) if helper_name is not None else None
        if resolved_helper_names is not None and resolved_helper_names & {"vars", "builtins.vars"}:
            target_root_node = namespace_node.args[0]

    if target_root_node is not None:
        global_builtin_roots = _resolve_global_builtin_namespace_roots(target_root_node, alias_scopes)
        if global_builtin_roots is not None:
            return global_builtin_roots
        target_root = _resolve_call_name(target_root_node)
        return _apply_aliases(target_root, alias_scopes) if target_root is not None else None

    namespace_name = _resolve_call_name(namespace_node)
    resolved_namespace_names = _apply_aliases(namespace_name, alias_scopes) if namespace_name is not None else None
    if resolved_namespace_names is not None:
        roots = {
            resolved_name.removesuffix(".__dict__")
            for resolved_name in resolved_namespace_names
            if resolved_name.endswith(".__dict__")
        }
        roots.update(
            resolved_name for resolved_name in resolved_namespace_names if resolved_name in _BUILTIN_NAMESPACE_NAMES
        )
        if roots:
            return frozenset(roots)

    resolved_namespace_names = _resolve_getattr_call_names(namespace_node, alias_scopes)
    if resolved_namespace_names is None:
        resolved_namespace_names = _resolve_dunder_getattribute_call_names(namespace_node, alias_scopes)
    if resolved_namespace_names is None:
        return None

    roots = {
        resolved_name.removesuffix(".__dict__")
        for resolved_name in resolved_namespace_names
        if resolved_name.endswith(".__dict__")
    }
    return frozenset(roots) if roots else None


def _resolve_namespace_dict_call_names(node: ast.AST, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    """Resolve bounded calls dispatched through a statically known namespace mapping."""
    if isinstance(node, ast.Attribute) and node.attr == "__call__":
        return _resolve_namespace_dict_call_names(node.value, alias_scopes)

    namespace_node: ast.AST | None = None
    attr_name_node: ast.AST
    resolved_target_roots: frozenset[str] | None = None
    if isinstance(node, ast.Subscript):
        namespace_node = node.value
        attr_name_node = node.slice
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _NAMESPACE_MAPPING_ACCESSORS
        and node.args
    ):
        namespace_node = node.func.value
        attr_name_node = node.args[0]
    elif isinstance(node, ast.Call) and node.args:
        accessor_roots = _resolve_aliased_mapping_accessor_roots(node, alias_scopes)
        if accessor_roots is None:
            return None
        roots = {
            accessor_root.removesuffix(".__dict__")
            for accessor_root in accessor_roots
            if accessor_root.endswith(".__dict__")
        }
        roots.update(
            accessor_root
            for accessor_root in accessor_roots
            if accessor_root in _BUILTIN_NAMESPACE_NAMES or accessor_root == "builtins"
        )
        if not roots:
            return None
        resolved_target_roots = frozenset(roots)
        attr_name_node = node.args[0]
    else:
        return None

    attr_name = _resolve_static_string(attr_name_node)
    if attr_name is None:
        return None

    if resolved_target_roots is None:
        assert namespace_node is not None
        resolved_target_roots = _resolve_namespace_dict_roots(namespace_node, alias_scopes)
    if resolved_target_roots is None:
        return None
    return frozenset(f"{resolved_target_root}.{attr_name}" for resolved_target_root in resolved_target_roots)


def _resolve_bound_namespace_accessor_names(node: ast.AST, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    """Resolve aliased accessor methods on known global or builtin mappings."""
    if not isinstance(node, ast.Attribute) or node.attr not in _NAMESPACE_MAPPING_ACCESSORS:
        return None

    target_roots = _resolve_global_namespace_mappings(node.value, alias_scopes)
    if target_roots is None:
        target_roots = _resolve_global_builtin_namespace_roots(node.value, alias_scopes)
    if target_roots is None:
        return None
    return frozenset(f"{target_root}.{node.attr}" for target_root in target_roots)


def _resolve_static_reference_names(node: ast.AST, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    global_namespace_mappings = _resolve_global_namespace_mappings(node, alias_scopes)
    if global_namespace_mappings is not None:
        return global_namespace_mappings
    bound_namespace_accessors = _resolve_bound_namespace_accessor_names(node, alias_scopes)
    if bound_namespace_accessors is not None:
        return bound_namespace_accessors
    call_name = _resolve_call_name(node)
    if call_name is not None:
        return _apply_aliases(call_name, alias_scopes)
    getattr_names = _resolve_getattr_call_names(node, alias_scopes)
    if getattr_names is not None:
        return getattr_names
    getattribute_names = _resolve_dunder_getattribute_call_names(node, alias_scopes)
    if getattribute_names is not None:
        return getattribute_names
    namespace_call_names = _resolve_namespace_dict_call_names(node, alias_scopes)
    if namespace_call_names is not None:
        return namespace_call_names
    namespace_roots = _resolve_namespace_dict_roots(node, alias_scopes)
    return frozenset(f"{namespace_root}.__dict__" for namespace_root in namespace_roots) if namespace_roots else None


def _resolve_static_assignment_target_names(node: ast.AST, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    """Resolve member targets whose later static call identity can be overwritten."""
    if isinstance(node, ast.Attribute):
        return _resolve_static_attribute_names(node.value, ast.Constant(value=node.attr), alias_scopes)
    if isinstance(node, ast.Subscript):
        return _resolve_static_reference_names(node, alias_scopes)
    return None


def _is_high_risk_python_call_name(name: str) -> bool:
    return name in _HIGH_RISK_PYTHON_CALLS or name.startswith("subprocess.")


def _wildcard_import_aliases(
    module: str, tracked_call_names: frozenset[str] | None = None
) -> Iterator[tuple[str, str]]:
    prefix = f"{module}."
    for call_name in sorted(_HIGH_RISK_PYTHON_CALLS if tracked_call_names is None else tracked_call_names):
        if not call_name.startswith(prefix):
            continue
        exported_name = call_name.removeprefix(prefix).split(".", maxsplit=1)[0]
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
    def __init__(self, tracked_call_names: frozenset[str] | None = None) -> None:
        self.alias_scopes: _AliasScopes = [{}]
        self._class_scope_ids: set[int] = set()
        self.risky_calls: set[str] = set()
        self.tracked_call_names = tracked_call_names

    def _bind_import_name(self, local_name: str, import_name: str) -> None:
        effective_names = self._effective_reference_names(frozenset({import_name}))
        self._bind_name(local_name, self._capture_callable_names(effective_names))

    def _record_import(self, alias: ast.alias, import_name: str) -> None:
        self._bind_import_name(alias.asname or alias.name, import_name)

    def _bind_name(self, name: str, resolved_names: _AliasValue) -> None:
        self.alias_scopes[-1][name] = resolved_names
        if not name.startswith("<"):
            self.alias_scopes[-1][self._static_uncertain_binding_key(name)] = frozenset()
            if self._lookup_static_mapping_mutation_alias(name) is not None:
                self.alias_scopes[-1][self._static_mapping_mutation_alias_key(name)] = None

    @staticmethod
    def _static_reference_override_key(reference_name: str) -> str:
        return f"{_STATIC_REFERENCE_OVERRIDE_PREFIX}{reference_name}"

    @staticmethod
    def _static_mapping_mutation_alias_key(name: str) -> str:
        return f"{_STATIC_MAPPING_MUTATION_ALIAS_PREFIX}{name}"

    @staticmethod
    def _static_uncertain_binding_key(name: str) -> str:
        return f"{_STATIC_UNCERTAIN_BINDING_PREFIX}{name}"

    def _lookup_static_reference_override(self, reference_name: str) -> _AliasValue:
        override_key = self._static_reference_override_key(reference_name)
        for aliases in reversed(self.alias_scopes):
            if override_key in aliases:
                return aliases[override_key]
        return frozenset({reference_name})

    def _lookup_static_mapping_mutation_alias(self, name: str) -> _AliasValue:
        alias_key = self._static_mapping_mutation_alias_key(name)
        for aliases in reversed(self.alias_scopes):
            if alias_key in aliases:
                return aliases[alias_key]
        return None

    def _resolve_certain_static_mapping_mutator_names(self, node: ast.AST) -> frozenset[str] | None:
        mutator_names = _resolve_static_mapping_mutator_names(node, self.alias_scopes)
        if mutator_names is not None:
            return mutator_names
        if isinstance(node, ast.Name):
            return self._lookup_static_mapping_mutation_alias(node.id)
        return None

    def _is_tracked_call_name(self, name: str) -> bool:
        return (
            name in self.tracked_call_names
            if self.tracked_call_names is not None
            else _is_high_risk_python_call_name(name)
        )

    @staticmethod
    def _captured_callable_reference_name(name: str) -> str:
        return f"{_CAPTURED_CALLABLE_REFERENCE_PREFIX}{name}"

    def _capture_callable_names(self, resolved_names: _AliasValue) -> _AliasValue:
        if resolved_names is None:
            return None
        return frozenset(
            self._captured_callable_reference_name(name) if self._is_tracked_call_name(name) else name
            for name in resolved_names
        )

    def _effective_reference_names(self, resolved_names: frozenset[str]) -> frozenset[str] | None:
        effective_names: set[str] = set()
        for resolved_name in resolved_names:
            if resolved_name.startswith(_CAPTURED_CALLABLE_REFERENCE_PREFIX):
                effective_names.add(resolved_name.removeprefix(_CAPTURED_CALLABLE_REFERENCE_PREFIX))
                continue
            override_names = self._lookup_static_reference_override(resolved_name)
            if override_names is not None:
                effective_names.update(
                    override_name.removeprefix(_CAPTURED_CALLABLE_REFERENCE_PREFIX)
                    if override_name.startswith(_CAPTURED_CALLABLE_REFERENCE_PREFIX)
                    else override_name
                    for override_name in override_names
                )
        return frozenset(effective_names) if effective_names else None

    @staticmethod
    def _invoked_callable_reference_name(name: str) -> str:
        while name.endswith(".__call__"):
            name = name.removesuffix(".__call__")
        return name

    def _resolve_invoked_reference_names(self, node: ast.AST) -> frozenset[str] | None:
        resolved_names = _resolve_static_reference_names(node, self.alias_scopes)
        if resolved_names is None:
            return None
        callable_names = frozenset(self._invoked_callable_reference_name(name) for name in resolved_names)
        return self._effective_reference_names(callable_names)

    def _resolve_bound_value_names(self, node: ast.AST) -> _AliasValue:
        return self._capture_callable_names(self._resolve_invoked_reference_names(node))

    def _bind_static_reference_target_to_value(self, target: ast.AST, value: ast.AST) -> None:
        if _has_uncertain_static_binding(target, self.alias_scopes):
            return
        target_names = _resolve_static_assignment_target_names(target, self.alias_scopes)
        if target_names is None:
            return

        self._bind_static_reference_names_to_value(target_names, value)

    def _bind_static_reference_names_to_value(self, target_names: frozenset[str], value: ast.AST) -> None:
        resolved_value_names = self._resolve_bound_value_names(value)
        for target_name in target_names:
            self._bind_name(self._static_reference_override_key(target_name), resolved_value_names)

    def _bind_static_reference_names_as_removed(self, target_names: frozenset[str]) -> None:
        for target_name in target_names:
            self._bind_name(self._static_reference_override_key(target_name), None)

    def _bind_static_reference_target_as_removed(self, target: ast.AST) -> None:
        if _has_uncertain_static_binding(target, self.alias_scopes):
            return
        target_names = _resolve_static_assignment_target_names(target, self.alias_scopes)
        if target_names is not None:
            self._bind_static_reference_names_as_removed(target_names)

    def _bind_static_mapping_mutation(self, node: ast.Call, *, model_discarded_removals: bool = False) -> None:
        """Model unconditional writes through one certain namespace mapping."""
        if node.keywords:
            return

        mutator_names = self._resolve_certain_static_mapping_mutator_names(node.func)
        mutation_args = node.args
        if mutator_names is not None:
            methods = {mutator_name.rsplit(".", maxsplit=1)[1] for mutator_name in mutator_names}
            if len(methods) != 1:
                return
            method = next(iter(methods))
            target_roots = frozenset(mutator_name.rsplit(".", maxsplit=1)[0] for mutator_name in mutator_names)
        else:
            if _has_uncertain_static_binding(node.func, self.alias_scopes) or not node.args:
                return
            helper_names = self._resolve_invoked_reference_names(node.func)
            if helper_names is None:
                return
            helper_methods = {_STATIC_MAPPING_FUNCTION_MUTATORS.get(helper_name) for helper_name in helper_names}
            if None in helper_methods or len(helper_methods) != 1:
                return
            method = next(helper_method for helper_method in helper_methods if helper_method is not None)
            resolved_target_roots = _resolve_certain_namespace_mutation_roots(node.args[0], self.alias_scopes)
            if resolved_target_roots is None:
                return
            target_roots = resolved_target_roots
            mutation_args = node.args[1:]

        mutations: list[tuple[frozenset[str], ast.AST | None]] = []
        if method == "__setitem__":
            if len(mutation_args) != 2:
                return
            attr_name = _resolve_static_string(mutation_args[0])
            if attr_name is None:
                return
            mutations.append(
                (frozenset(f"{target_root}.{attr_name}" for target_root in target_roots), mutation_args[1])
            )
        elif method == "__delitem__":
            if len(mutation_args) != 1:
                return
            attr_name = _resolve_static_string(mutation_args[0])
            if attr_name is None:
                return
            mutations.append((frozenset(f"{target_root}.{attr_name}" for target_root in target_roots), None))
        elif method == "update":
            if len(mutation_args) != 1 or not isinstance(mutation_args[0], ast.Dict):
                return
            for attr_name_node, value_node in zip(mutation_args[0].keys, mutation_args[0].values, strict=True):
                if attr_name_node is None:
                    return
                attr_name = _resolve_static_string(attr_name_node)
                if attr_name is None:
                    return
                mutations.append((frozenset(f"{target_root}.{attr_name}" for target_root in target_roots), value_node))
        elif method == "pop":
            if not model_discarded_removals or len(mutation_args) not in {1, 2}:
                return
            attr_name = _resolve_static_string(mutation_args[0])
            if attr_name is None:
                return
            mutations.append((frozenset(f"{target_root}.{attr_name}" for target_root in target_roots), None))
        else:
            return

        for target_names, value in mutations:
            if value is None:
                self._bind_static_reference_names_as_removed(target_names)
            else:
                self._bind_static_reference_names_to_value(target_names, value)

    def _bind_static_setattr_mutation(self, node: ast.Call) -> None:
        """Model certain builtin ``setattr`` writes to one resolved reference."""
        if len(node.args) != 3 or node.keywords:
            return
        if _has_uncertain_static_binding(node.args[0], self.alias_scopes):
            return

        helper_names = self._resolve_invoked_reference_names(node.func)
        if helper_names is None or not helper_names.issubset(_STATIC_ATTRIBUTE_MUTATION_HELPERS):
            return

        target_names = _resolve_static_attribute_names(node.args[0], node.args[1], self.alias_scopes)
        if target_names is None or len(target_names) != 1:
            return
        self._bind_static_reference_names_to_value(target_names, node.args[2])

    def _bind_target_to_value(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            value_binding_is_uncertain = _has_uncertain_static_binding(value, self.alias_scopes)
            self._bind_name(target.id, self._resolve_bound_value_names(value))
            if value_binding_is_uncertain:
                self.alias_scopes[-1][self._static_uncertain_binding_key(target.id)] = None
            mutator_names = self._resolve_certain_static_mapping_mutator_names(value)
            if mutator_names is not None:
                self._bind_name(self._static_mapping_mutation_alias_key(target.id), mutator_names)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            self._bind_static_reference_target_to_value(target, value)
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

    def _shadow_binding_target(self, target: ast.AST) -> None:
        for name in _binding_names(target):
            self._bind_name(name, None)

    def _bind_arguments(self, arguments: ast.arguments) -> None:
        positional_args = [*arguments.posonlyargs, *arguments.args]
        positional_default_start = len(positional_args) - len(arguments.defaults)
        for index, arg in enumerate(positional_args):
            default = (
                arguments.defaults[index - positional_default_start] if index >= positional_default_start else None
            )
            self._bind_name(
                arg.arg,
                self._resolve_bound_value_names(default) if default is not None else None,
            )
            self.alias_scopes[-1][self._static_uncertain_binding_key(arg.arg)] = None
        for arg, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True):
            self._bind_name(
                arg.arg,
                self._resolve_bound_value_names(default) if default is not None else None,
            )
            self.alias_scopes[-1][self._static_uncertain_binding_key(arg.arg)] = None
        if arguments.vararg is not None:
            self._bind_name(arguments.vararg.arg, None)
            self.alias_scopes[-1][self._static_uncertain_binding_key(arguments.vararg.arg)] = None
        if arguments.kwarg is not None:
            self._bind_name(arguments.kwarg.arg, None)
            self.alias_scopes[-1][self._static_uncertain_binding_key(arguments.kwarg.arg)] = None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._record_import(alias, alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            return
        for alias in node.names:
            if alias.name == "*":
                for local_name, import_name in _wildcard_import_aliases(node.module, self.tracked_call_names):
                    self._bind_import_name(local_name, import_name)
                continue
            self._record_import(alias, f"{node.module}.{alias.name}")

    def _visit_child_scope(self, body: list[ast.stmt]) -> None:
        self.alias_scopes.append({})
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self.alias_scopes.pop()

    def _visit_conditional_branch(self, body: list[ast.stmt]) -> _AliasScope:
        branch_scope: _AliasScope = {}
        parent_is_class_scope = id(self.alias_scopes[-1]) in self._class_scope_ids
        self.alias_scopes.append(branch_scope)
        if parent_is_class_scope:
            self._class_scope_ids.add(id(branch_scope))
        try:
            for statement in body:
                self.visit(statement)
            return dict(branch_scope)
        finally:
            if parent_is_class_scope:
                self._class_scope_ids.discard(id(branch_scope))
            self.alias_scopes.pop()

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
            if name.startswith(_STATIC_UNCERTAIN_BINDING_PREFIX):
                uncertainty_base_value = current_scope.get(name, frozenset())
                uncertainty_values = [scope.get(name, uncertainty_base_value) for scope in branch_scopes]
                current_scope[name] = (
                    None
                    if current_scope.get(name) is None or any(value is None for value in uncertainty_values)
                    else frozenset()
                )
                continue
            if name.startswith(_STATIC_MAPPING_MUTATION_ALIAS_PREFIX):
                certainty_base_value: _AliasValue | object = current_scope.get(name, _MISSING_ALIAS)
                certainty_values = [scope.get(name, certainty_base_value) for scope in branch_scopes]
                first_value = certainty_values[0]
                current_scope[name] = (
                    first_value
                    if isinstance(first_value, frozenset) and all(value == first_value for value in certainty_values)
                    else None
                )
                continue
            base_value: _AliasValue | object
            if name.startswith(_STATIC_REFERENCE_OVERRIDE_PREFIX):
                base_value = self._lookup_static_reference_override(
                    name.removeprefix(_STATIC_REFERENCE_OVERRIDE_PREFIX)
                )
            else:
                base_value = current_scope.get(name, _MISSING_ALIAS)
            branch_values = [scope.get(name, base_value) for scope in branch_scopes]
            if not name.startswith("<") and any(value != branch_values[0] for value in branch_values[1:]):
                current_scope[self._static_uncertain_binding_key(name)] = None
            concrete_aliases = frozenset(
                alias for value in branch_values if isinstance(value, frozenset) for alias in value
            )
            if concrete_aliases:
                current_scope[name] = concrete_aliases
            elif any(value is None for value in branch_values):
                current_scope[name] = None

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
        self.alias_scopes.append(class_scope)
        self._class_scope_ids.add(id(class_scope))
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self._class_scope_ids.discard(id(class_scope))
            self.alias_scopes.pop()

    def _visit_function_scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        if node.returns is not None:
            self.visit(node.returns)
        self.alias_scopes.append({})
        try:
            self._bind_arguments(node.args)
            self._visit_child_scope_without_class_locals(node.body)
        finally:
            self.alias_scopes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_scope(node)
        self._bind_name(node.name, None)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_scope(node)
        self._bind_name(node.name, None)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword)
        self._visit_class_scope(node.body)
        self._bind_name(node.name, None)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        self.alias_scopes.append({})
        try:
            self._bind_arguments(node.args)
            self.visit(node.body)
        finally:
            self.alias_scopes.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        if isinstance(node.value, ast.Call):
            self._bind_static_mapping_mutation(node.value)
            self._bind_static_setattr_mutation(node.value)
        for target in node.targets:
            self._bind_target_to_value(target, node.value)
            self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.annotation is not None:
            self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
            if isinstance(node.value, ast.Call):
                self._bind_static_mapping_mutation(node.value)
                self._bind_static_setattr_mutation(node.value)
            self._bind_target_to_value(node.target, node.value)
        else:
            self._shadow_binding_target(node.target)
        self.visit(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self._shadow_binding_target(node.target)
        self.visit(node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._bind_target_to_value(node.target, node.value)
        self.visit(node.target)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self._bind_static_reference_target_as_removed(target)
            self.visit(target)

    def visit_Expr(self, node: ast.Expr) -> None:
        self.visit(node.value)
        if isinstance(node.value, ast.Call):
            self._bind_static_mapping_mutation(node.value, model_discarded_removals=True)
            self._bind_static_setattr_mutation(node.value)

    def _visit_loop(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        iter_truth = self._literal_iter_truth(node.iter)
        if iter_truth is False:
            for statement in node.orelse:
                self.visit(statement)
            return

        body_scope: _AliasScope = {}
        self.alias_scopes.append(body_scope)
        try:
            self._shadow_binding_target(node.target)
            self.visit(node.target)
            for statement in node.body:
                self.visit(statement)
            body_scope = dict(body_scope)
        finally:
            self.alias_scopes.pop()
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
            self.alias_scopes.append(branch_scope)
            try:
                if handler.name is not None:
                    self._bind_name(handler.name, None)
                for statement in handler.body:
                    self.visit(statement)
                branch_scope = dict(branch_scope)
            finally:
                self.alias_scopes.pop()
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
        resolved_names = self._resolve_invoked_reference_names(node.func)
        if resolved_names is not None:
            for resolved_name in resolved_names:
                if self._is_tracked_call_name(resolved_name):
                    self.risky_calls.add(resolved_name)
        self.generic_visit(node)


def statically_resolved_python_call_names_in_tree(tree: ast.AST, tracked_call_names: frozenset[str]) -> set[str]:
    """Return caller-selected static call targets resolved from an AST."""
    visitor = _HighRiskPythonCallVisitor(tracked_call_names)
    visitor.visit(tree)
    return visitor.risky_calls


def high_risk_python_calls_in_tree(tree: ast.AST) -> set[HighRiskPythonCall]:
    """Return the set of high-risk Python calls resolvable from an AST."""
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


def scan_archive_member_for_known_risks(
    *,
    archive_kind: str,
    archive_path: str,
    member_name: str,
    tmp_path: str,
    total_size: int,
    result: ScanResult,
    max_python_analysis_bytes: int,
    python_analysis_incomplete_reason: str,
) -> None:
    """Inspect generic archive members that nested dispatch would otherwise ignore.

    ``archive_kind`` is a short label (``"ZIP"`` / ``"TAR"``) used only for the
    human-readable message text. The dispatcher (1) routes Python-looking
    members through bounded AST analysis, (2) flags native/script executable-
    suffix members, and (3) leaves everything else to the caller's normal
    nested routing.
    """
    normalized_name = member_name.replace("\\", "/").lstrip("/")
    normalized_lower = normalized_name.lower()
    location = f"{archive_path}:{member_name}"

    if is_python_archive_member_name(normalized_lower):
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
            return

        try:
            with open(tmp_path, "rb") as member_file:
                calls = high_risk_python_calls_in_source(member_file.read())
        except PythonArchiveMemberParseError as exc:
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
            result.add_check(
                name=_PYTHON_MEMBER_CHECK_NAME,
                passed=False,
                message=f"High-risk Python code found in {archive_kind} member {member_name}: {reason}",
                severity=IssueSeverity.WARNING,
                location=location,
                details={"entry": member_name, "reason": reason},
                rule_code=rule_code,
            )
        return

    executable_rule_code = executable_archive_member_rule_code(normalized_lower, path=tmp_path)
    if executable_rule_code is not None:
        result.add_check(
            name=_EXECUTABLE_MEMBER_CHECK_NAME,
            passed=False,
            message=f"Executable file found in {archive_kind} archive: {member_name}",
            severity=IssueSeverity.WARNING,
            location=location,
            details={"entry": member_name},
            rule_code=executable_rule_code,
        )
