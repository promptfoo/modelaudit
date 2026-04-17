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


class PythonArchiveMemberParseError(Exception):
    """Raised when Python member security analysis cannot parse source."""


def is_executable_archive_member_name(member_name: str) -> bool:
    """Return True when an archive member name has an executable/native-library suffix."""
    normalized_name = member_name.lower()
    return normalized_name.endswith(_EXECUTABLE_ARCHIVE_MEMBER_SUFFIXES) or bool(
        _VERSIONED_SHARED_OBJECT_SUFFIX_RE.search(normalized_name)
    )


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


def _resolve_alias(name: str, alias_scopes: list[dict[str, str]]) -> str:
    for aliases in reversed(alias_scopes):
        resolved = aliases.get(name)
        if resolved is not None:
            return resolved
    return name


def _apply_alias(call_name: str, alias_scopes: list[dict[str, str]]) -> str:
    head, *tail = call_name.split(".")
    resolved_head = _resolve_alias(head, alias_scopes)
    if not tail:
        return resolved_head
    return ".".join([resolved_head, *tail])


def _resolve_getattr_call_name(node: ast.AST, alias_scopes: list[dict[str, str]]) -> str | None:
    if isinstance(node, ast.Attribute) and node.attr == "__call__":
        return _resolve_getattr_call_name(node.value, alias_scopes)

    if not isinstance(node, ast.Call):
        return None

    helper_name = _resolve_call_name(node.func)
    if helper_name is None:
        return None

    resolved_helper_name = _apply_alias(helper_name, alias_scopes)
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

    resolved_target_root = _apply_alias(target_root, alias_scopes)
    return f"{resolved_target_root}.{attr_name_node.value}"


class _HighRiskPythonCallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.alias_scopes: list[dict[str, str]] = [{}]
        self.risky_calls: set[str] = set()

    def _record_import(self, alias: ast.alias, import_name: str) -> None:
        self.alias_scopes[-1][alias.asname or alias.name] = import_name

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._record_import(alias, alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            return
        for alias in node.names:
            self._record_import(alias, f"{node.module}.{alias.name}")

    def _visit_child_scope(self, body: list[ast.stmt]) -> None:
        self.alias_scopes.append({})
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self.alias_scopes.pop()

    def _visit_function_scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        if node.returns is not None:
            self.visit(node.returns)
        self._visit_child_scope(node.body)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_scope(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword)
        self._visit_child_scope(node.body)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        self.alias_scopes.append({})
        try:
            self.visit(node.body)
        finally:
            self.alias_scopes.pop()

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _resolve_call_name(node.func)
        resolved_name = (
            _apply_alias(call_name, self.alias_scopes)
            if call_name is not None
            else _resolve_getattr_call_name(node.func, self.alias_scopes)
        )
        if resolved_name is not None and (
            resolved_name in _HIGH_RISK_PYTHON_CALLS or resolved_name.startswith("subprocess.")
        ):
            self.risky_calls.add(resolved_name)
        self.generic_visit(node)


def _find_high_risk_python_calls(source_bytes: bytes) -> set[str]:
    source = source_bytes.decode("utf-8", "replace")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError) as exc:
        raise PythonArchiveMemberParseError(str(exc)) from exc

    visitor = _HighRiskPythonCallVisitor()
    visitor.visit(tree)
    return visitor.risky_calls


def dangerous_python_archive_member_reason(source_bytes: bytes) -> str | None:
    """Return a concise reason when Python source contains high-risk constructs."""
    risky_calls = _find_high_risk_python_calls(source_bytes)
    if not risky_calls:
        return None
    return f"high-risk calls: {', '.join(sorted(risky_calls))}"
