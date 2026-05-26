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
_STATIC_REFERENCE_OVERRIDE_PREFIX = "<static reference override>:"
_BUILTIN_NAMESPACE_NAMES = {"__builtin__", "__builtins__"}
_GLOBAL_NAMESPACE_MAPPING_NAME = "<globals>"
_UNKNOWN_ALIAS_NAME = "<unknown>"


def _resolve_global_namespace_mapping_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    require_definite: bool = False,
) -> frozenset[str] | None:
    """Resolve the module global namespace mapping returned by zero-argument ``globals()``."""
    if isinstance(node, ast.Call) and not node.args and not node.keywords:
        helper_name = _resolve_call_name(node.func)
        resolved_helper_names = _apply_aliases(helper_name, alias_scopes) if helper_name is not None else None
        if resolved_helper_names is not None and resolved_helper_names & _GLOBAL_NAMESPACE_HELPERS:
            if require_definite and not resolved_helper_names <= _GLOBAL_NAMESPACE_HELPERS:
                return None
            return frozenset({_GLOBAL_NAMESPACE_MAPPING_NAME})

    namespace_name = _resolve_call_name(node)
    resolved_namespace_names = _apply_aliases(namespace_name, alias_scopes) if namespace_name is not None else None
    if resolved_namespace_names is None:
        return None
    global_namespace_names = {
        resolved_namespace_name
        for resolved_namespace_name in resolved_namespace_names
        if resolved_namespace_name == _GLOBAL_NAMESPACE_MAPPING_NAME
    }
    if require_definite and global_namespace_names != resolved_namespace_names:
        return None
    return frozenset(global_namespace_names) if global_namespace_names else None


def _resolve_aliased_mapping_accessor_roots(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    require_definite: bool = False,
) -> frozenset[str] | None:
    """Resolve receivers for a statically aliased mapping accessor invocation."""
    if not isinstance(node, ast.Call) or not node.args:
        return None

    helper_name = _resolve_call_name(node.func)
    resolved_helper_names = _apply_aliases(helper_name, alias_scopes) if helper_name is not None else None
    if resolved_helper_names is None:
        return None

    normalized_helper_names = frozenset(
        resolved_helper_name.removesuffix(".__call__") for resolved_helper_name in resolved_helper_names
    )
    accessor_helper_names = frozenset(
        resolved_helper_name
        for resolved_helper_name in normalized_helper_names
        if "." in resolved_helper_name
        and resolved_helper_name.rsplit(".", maxsplit=1)[1] in _NAMESPACE_MAPPING_ACCESSORS
    )
    if require_definite and accessor_helper_names != normalized_helper_names:
        return None
    roots = {accessor_helper_name.rsplit(".", maxsplit=1)[0] for accessor_helper_name in accessor_helper_names}
    return frozenset(roots) if roots else None


def _resolve_global_builtin_namespace_roots(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    require_definite: bool = False,
) -> frozenset[str] | None:
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
        accessor_roots = _resolve_aliased_mapping_accessor_roots(
            node,
            alias_scopes,
            require_definite=require_definite,
        )
        if accessor_roots is None:
            return None
        global_namespace_roots = {
            accessor_root for accessor_root in accessor_roots if accessor_root == _GLOBAL_NAMESPACE_MAPPING_NAME
        }
        if require_definite and global_namespace_roots != accessor_roots:
            return None
        if not global_namespace_roots:
            return None
        namespace_node = None
        attr_name_node = node.args[0]
    else:
        return None

    attr_name = _resolve_static_string(attr_name_node)
    if attr_name not in _BUILTIN_NAMESPACE_NAMES:
        return None
    if namespace_node is not None:
        global_namespace_names = _resolve_global_namespace_mapping_names(
            namespace_node,
            alias_scopes,
            require_definite=require_definite,
        )
        if global_namespace_names is None:
            return None
    return frozenset({attr_name})


def _resolve_static_attribute_names(
    target_root_node: ast.AST,
    attr_name_node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    require_definite: bool = False,
) -> frozenset[str] | None:
    attr_name = _resolve_static_string(attr_name_node)
    if attr_name is None:
        return None

    resolved_target_roots = _resolve_global_builtin_namespace_roots(
        target_root_node,
        alias_scopes,
        require_definite=require_definite,
    )
    if resolved_target_roots is None:
        target_root = _resolve_call_name(target_root_node)
        if target_root is None:
            return None
        resolved_target_roots = _apply_aliases(target_root, alias_scopes)
    if resolved_target_roots is None:
        return None
    return frozenset(f"{resolved_target_root}.{attr_name}" for resolved_target_root in resolved_target_roots)


def _resolve_getattr_call_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    require_definite: bool = False,
) -> frozenset[str] | None:
    # Resolve literal names and compile-time string concatenation. Runtime-built
    # names still fall outside this static member analysis by design.
    if isinstance(node, ast.Attribute) and node.attr == "__call__":
        return _resolve_getattr_call_names(node.value, alias_scopes, require_definite=require_definite)

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

    return _resolve_static_attribute_names(
        target_root_node,
        attr_name_node,
        alias_scopes,
        require_definite=require_definite,
    )


def _resolve_dunder_getattribute_call_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    require_definite: bool = False,
) -> frozenset[str] | None:
    if isinstance(node, ast.Attribute) and node.attr == "__call__":
        return _resolve_dunder_getattribute_call_names(
            node.value,
            alias_scopes,
            require_definite=require_definite,
        )

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
        return _resolve_static_attribute_names(
            node.args[0],
            node.args[1],
            alias_scopes,
            require_definite=require_definite,
        )

    if not isinstance(node.func, ast.Attribute) or node.func.attr != "__getattribute__" or not node.args:
        return None
    return _resolve_static_attribute_names(
        node.func.value,
        node.args[0],
        alias_scopes,
        require_definite=require_definite,
    )


def _resolve_namespace_dict_roots(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    require_definite: bool = False,
) -> frozenset[str] | None:
    global_builtin_roots = _resolve_global_builtin_namespace_roots(
        node,
        alias_scopes,
        require_definite=require_definite,
    )
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
        global_builtin_roots = _resolve_global_builtin_namespace_roots(
            target_root_node,
            alias_scopes,
            require_definite=require_definite,
        )
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
        if require_definite and roots != resolved_namespace_names:
            return None
        if roots:
            return frozenset(roots)

    resolved_namespace_names = _resolve_getattr_call_names(
        namespace_node,
        alias_scopes,
        require_definite=require_definite,
    )
    if resolved_namespace_names is None:
        resolved_namespace_names = _resolve_dunder_getattribute_call_names(
            namespace_node,
            alias_scopes,
            require_definite=require_definite,
        )
    if resolved_namespace_names is None:
        return None

    roots = {
        resolved_name.removesuffix(".__dict__")
        for resolved_name in resolved_namespace_names
        if resolved_name.endswith(".__dict__")
    }
    if require_definite and roots != resolved_namespace_names:
        return None
    return frozenset(roots) if roots else None


def _resolve_namespace_dict_call_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    require_definite: bool = False,
) -> frozenset[str] | None:
    """Resolve bounded calls dispatched through a statically known namespace mapping."""
    if isinstance(node, ast.Attribute) and node.attr == "__call__":
        return _resolve_namespace_dict_call_names(
            node.value,
            alias_scopes,
            require_definite=require_definite,
        )

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
        accessor_roots = _resolve_aliased_mapping_accessor_roots(
            node,
            alias_scopes,
            require_definite=require_definite,
        )
        if accessor_roots is None:
            return None
        roots = {
            accessor_root.removesuffix(".__dict__")
            for accessor_root in accessor_roots
            if accessor_root.endswith(".__dict__")
        }
        roots.update(accessor_root for accessor_root in accessor_roots if accessor_root in _BUILTIN_NAMESPACE_NAMES)
        if require_definite and roots != accessor_roots:
            return None
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
        resolved_target_roots = _resolve_namespace_dict_roots(
            namespace_node,
            alias_scopes,
            require_definite=require_definite,
        )
    if resolved_target_roots is None:
        return None
    return frozenset(f"{resolved_target_root}.{attr_name}" for resolved_target_root in resolved_target_roots)


def _resolve_bound_namespace_accessor_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    require_definite: bool = False,
) -> frozenset[str] | None:
    """Resolve aliased accessor methods on known global or builtin mappings."""
    if not isinstance(node, ast.Attribute) or node.attr not in _NAMESPACE_MAPPING_ACCESSORS:
        return None

    target_roots = _resolve_global_namespace_mapping_names(
        node.value,
        alias_scopes,
        require_definite=require_definite,
    )
    if target_roots is None:
        target_roots = _resolve_global_builtin_namespace_roots(
            node.value,
            alias_scopes,
            require_definite=require_definite,
        )
    if target_roots is not None:
        return frozenset(f"{target_root}.{node.attr}" for target_root in target_roots)

    namespace_dict_roots = _resolve_namespace_dict_roots(
        node.value,
        alias_scopes,
        require_definite=require_definite,
    )
    if namespace_dict_roots is None:
        return None
    return frozenset(f"{target_root}.__dict__.{node.attr}" for target_root in namespace_dict_roots)


def _resolve_static_reference_names(
    node: ast.AST,
    alias_scopes: _AliasScopes,
    *,
    require_definite: bool = False,
) -> frozenset[str] | None:
    global_namespace_names = _resolve_global_namespace_mapping_names(
        node,
        alias_scopes,
        require_definite=require_definite,
    )
    if global_namespace_names is not None:
        return global_namespace_names
    bound_namespace_accessors = _resolve_bound_namespace_accessor_names(
        node,
        alias_scopes,
        require_definite=require_definite,
    )
    if bound_namespace_accessors is not None:
        return bound_namespace_accessors
    call_name = _resolve_call_name(node)
    if call_name is not None:
        return _apply_aliases(call_name, alias_scopes)
    global_builtin_roots = _resolve_global_builtin_namespace_roots(
        node,
        alias_scopes,
        require_definite=require_definite,
    )
    if global_builtin_roots is not None:
        return global_builtin_roots
    if isinstance(node, ast.Attribute):
        attribute_names = _resolve_static_attribute_names(
            node.value,
            ast.Constant(node.attr),
            alias_scopes,
            require_definite=require_definite,
        )
        if attribute_names is not None:
            return attribute_names
    getattr_names = _resolve_getattr_call_names(node, alias_scopes, require_definite=require_definite)
    if getattr_names is not None:
        return getattr_names
    getattribute_names = _resolve_dunder_getattribute_call_names(
        node,
        alias_scopes,
        require_definite=require_definite,
    )
    if getattribute_names is not None:
        return getattribute_names
    namespace_call_names = _resolve_namespace_dict_call_names(
        node,
        alias_scopes,
        require_definite=require_definite,
    )
    if namespace_call_names is not None:
        return namespace_call_names
    namespace_roots = _resolve_namespace_dict_roots(node, alias_scopes, require_definite=require_definite)
    return frozenset(f"{namespace_root}.__dict__" for namespace_root in namespace_roots) if namespace_roots else None


def _resolve_static_assignment_target_names(node: ast.AST, alias_scopes: _AliasScopes) -> frozenset[str] | None:
    """Resolve member targets whose later static call identity can be overwritten."""
    if isinstance(node, ast.Attribute):
        target_names = _resolve_static_attribute_names(
            node.value,
            ast.Constant(value=node.attr),
            alias_scopes,
            require_definite=True,
        )
        return target_names if target_names is not None and len(target_names) == 1 else None
    if isinstance(node, ast.Subscript):
        target_names = _resolve_static_reference_names(node, alias_scopes, require_definite=True)
        return target_names if target_names is not None and len(target_names) == 1 else None
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

    def _record_import(self, alias: ast.alias, import_name: str) -> None:
        self.alias_scopes[-1][alias.asname or alias.name] = frozenset({import_name})

    def _bind_name(self, name: str, resolved_names: _AliasValue) -> None:
        self.alias_scopes[-1][name] = resolved_names

    @staticmethod
    def _static_reference_override_key(reference_name: str) -> str:
        return f"{_STATIC_REFERENCE_OVERRIDE_PREFIX}{reference_name}"

    def _lookup_static_reference_override(self, reference_name: str) -> _AliasValue:
        override_key = self._static_reference_override_key(reference_name)
        for aliases in reversed(self.alias_scopes):
            if override_key in aliases:
                return aliases[override_key]
        return frozenset({reference_name})

    def _resolve_reference_names(self, node: ast.AST) -> frozenset[str] | None:
        resolved_names = _resolve_static_reference_names(node, self.alias_scopes)
        if resolved_names is None:
            return None

        effective_names: set[str] = set()
        for resolved_name in resolved_names:
            override_names = self._lookup_static_reference_override(resolved_name)
            if override_names is not None:
                effective_names.update(override_names)
        return frozenset(effective_names) if effective_names else None

    def _bind_static_reference_target_to_value(self, target: ast.AST, value: ast.AST) -> None:
        target_names = _resolve_static_assignment_target_names(target, self.alias_scopes)
        if target_names is None:
            return

        self._bind_static_reference_names_to_value(target_names, value)

    def _bind_static_reference_names_to_value(self, target_names: frozenset[str], value: ast.AST) -> None:
        resolved_value_names = self._resolve_reference_names(value)
        for target_name in target_names:
            self._bind_name(
                self._static_reference_override_key(target_name),
                resolved_value_names if resolved_value_names is not None else frozenset({target_name}),
            )

    def _invalidate_static_reference_names(self, target_names: frozenset[str]) -> None:
        for target_name in target_names:
            self._bind_name(self._static_reference_override_key(target_name), frozenset({target_name}))

    def _invalidate_builtin_namespace_roots(self, target_roots: frozenset[str]) -> None:
        target_names = frozenset(
            call_name
            for target_root in target_roots
            for call_name in _HIGH_RISK_PYTHON_CALLS
            if call_name.startswith(f"{target_root}.")
        )
        if target_names:
            self._invalidate_static_reference_names(target_names)

    @staticmethod
    def _static_update_pair_nodes(node: ast.AST) -> Iterator[tuple[ast.AST, ast.AST] | None]:
        if isinstance(node, ast.Dict):
            for key_node, value_node in zip(node.keys, node.values, strict=True):
                if key_node is not None:
                    yield key_node, value_node
                elif not isinstance(value_node, ast.Dict) or value_node.keys:
                    yield None
            return
        if isinstance(node, (ast.List, ast.Tuple)):
            for element in node.elts:
                if isinstance(element, (ast.List, ast.Tuple)) and len(element.elts) == 2:
                    yield element.elts[0], element.elts[1]
                else:
                    yield None
            return
        yield None

    def _bind_direct_builtin_namespace_mutation(self, node: ast.Call) -> None:
        """Model unconditional mutations of a directly addressed builtin mapping."""
        if not isinstance(node.func, ast.Attribute):
            return

        target_roots = _resolve_namespace_dict_roots(
            node.func.value,
            self.alias_scopes,
            require_definite=True,
        )
        if target_roots is None:
            return

        mutations: list[tuple[frozenset[str], ast.AST]] = []
        should_invalidate = False
        if node.func.attr == "__setitem__":
            if len(node.args) != 2 or node.keywords:
                return
            attr_name = _resolve_static_string(node.args[0])
            if attr_name is None:
                self._invalidate_builtin_namespace_roots(target_roots)
                return
            mutations.append((frozenset(f"{target_root}.{attr_name}" for target_root in target_roots), node.args[1]))
        elif node.func.attr == "update":
            if len(node.args) > 1:
                self._invalidate_builtin_namespace_roots(target_roots)
                return
            if node.args:
                for pair_nodes in self._static_update_pair_nodes(node.args[0]):
                    if pair_nodes is None:
                        should_invalidate = True
                        continue
                    attr_name_node, value_node = pair_nodes
                    attr_name = _resolve_static_string(attr_name_node)
                    if attr_name is None:
                        should_invalidate = True
                        continue
                    mutations.append(
                        (frozenset(f"{target_root}.{attr_name}" for target_root in target_roots), value_node)
                    )
            for keyword in node.keywords:
                if keyword.arg is None:
                    should_invalidate = True
                    continue
                mutations.append(
                    (frozenset(f"{target_root}.{keyword.arg}" for target_root in target_roots), keyword.value)
                )
        else:
            return

        for target_names, value in mutations:
            self._bind_static_reference_names_to_value(target_names, value)
        if should_invalidate:
            self._invalidate_builtin_namespace_roots(target_roots)

    def _bind_target_to_value(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self._bind_name(target.id, self._resolve_reference_names(value))
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
                self._resolve_reference_names(default) if default is not None else None,
            )
        for arg, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True):
            self._bind_name(
                arg.arg,
                self._resolve_reference_names(default) if default is not None else None,
            )
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
                for local_name, import_name in _wildcard_import_aliases(node.module, self.tracked_call_names):
                    self._bind_name(local_name, frozenset({import_name}))
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
            base_value: _AliasValue | object
            if name.startswith(_STATIC_REFERENCE_OVERRIDE_PREFIX):
                base_value = self._lookup_static_reference_override(
                    name.removeprefix(_STATIC_REFERENCE_OVERRIDE_PREFIX)
                )
            else:
                base_value = current_scope.get(name, _MISSING_ALIAS)
            values = [scope.get(name, base_value) for scope in branch_scopes]
            concrete_aliases = frozenset(alias for value in values if isinstance(value, frozenset) for alias in value)
            if concrete_aliases:
                if any(value is None for value in values):
                    current_scope[name] = concrete_aliases | frozenset({_UNKNOWN_ALIAS_NAME})
                else:
                    current_scope[name] = concrete_aliases
            elif any(value is None for value in values):
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

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self._shadow_binding_target(node.target)
        self.visit(node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._bind_target_to_value(node.target, node.value)
        self.visit(node.target)

    def visit_Expr(self, node: ast.Expr) -> None:
        self.visit(node.value)

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
        resolved_names = self._resolve_reference_names(node.func)
        if resolved_names is not None:
            for resolved_name in resolved_names:
                if (
                    resolved_name in self.tracked_call_names
                    if self.tracked_call_names is not None
                    else _is_high_risk_python_call_name(resolved_name)
                ):
                    self.risky_calls.add(resolved_name)
        self.generic_visit(node)
        self._bind_direct_builtin_namespace_mutation(node)


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
