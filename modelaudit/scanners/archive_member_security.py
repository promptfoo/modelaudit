"""Shared security helpers for archive member names."""

import ast
import re

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
_VERSIONED_SHARED_OBJECT_SUFFIX_RE = re.compile(r"\.so(?:\.[0-9]+)+$")
_PYTHON_ARCHIVE_MEMBER_SUFFIXES = (".py", ".pyw")
_HIGH_RISK_PYTHON_CALLS = {
    "__import__",
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


def is_executable_archive_member_name(member_name: str) -> bool:
    """Return True when an archive member name has an executable/native-library suffix."""
    normalized_name = member_name.lower()
    return normalized_name.endswith(_EXECUTABLE_ARCHIVE_MEMBER_SUFFIXES) or bool(
        _VERSIONED_SHARED_OBJECT_SUFFIX_RE.search(normalized_name)
    )


def is_python_archive_member_name(member_name: str) -> bool:
    """Return True when an archive member name looks like Python source."""
    return member_name.lower().endswith(_PYTHON_ARCHIVE_MEMBER_SUFFIXES)


def _collect_import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _resolve_call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _resolve_call_name(node.value)
        if parent is None:
            return None
        return f"{parent}.{node.attr}"
    return None


def _apply_alias(call_name: str, aliases: dict[str, str]) -> str:
    head, *tail = call_name.split(".")
    resolved_head = aliases.get(head, head)
    if not tail:
        return resolved_head
    return ".".join([resolved_head, *tail])


def _resolve_getattr_call_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Attribute) and node.attr == "__call__":
        return _resolve_getattr_call_name(node.value, aliases)

    if not isinstance(node, ast.Call):
        return None

    helper_name = _resolve_call_name(node.func)
    if helper_name is None:
        return None

    resolved_helper_name = _apply_alias(helper_name, aliases)
    if resolved_helper_name not in {"getattr", "builtins.getattr"}:
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

    target_root = _resolve_call_name(target_root_node)
    if target_root is None:
        return None

    if not isinstance(attr_name_node, ast.Constant) or not isinstance(attr_name_node.value, str):
        return None

    resolved_target_root = _apply_alias(target_root, aliases)
    return f"{resolved_target_root}.{attr_name_node.value}"


def _find_high_risk_python_calls(source_bytes: bytes) -> set[str]:
    source = source_bytes.decode("utf-8", "replace")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return set()

    aliases = _collect_import_aliases(tree)
    risky_calls: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_name = _resolve_call_name(node.func)
        resolved_name = (
            _apply_alias(call_name, aliases)
            if call_name is not None
            else _resolve_getattr_call_name(node.func, aliases)
        )
        if resolved_name is None:
            continue
        if resolved_name in _HIGH_RISK_PYTHON_CALLS or resolved_name.startswith("subprocess."):
            risky_calls.add(resolved_name)

    return risky_calls


def dangerous_python_archive_member_reason(source_bytes: bytes) -> str | None:
    """Return a concise reason when Python source contains high-risk constructs."""
    risky_calls = _find_high_risk_python_calls(source_bytes)
    if not risky_calls:
        return None
    return f"high-risk calls: {', '.join(sorted(risky_calls))}"
