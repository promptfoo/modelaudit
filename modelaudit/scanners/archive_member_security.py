"""Shared security helpers for archive member names and source analysis."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

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


_AliasScope = dict[str, str | None]
_AliasScopes = list[_AliasScope]


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


def _resolve_alias(name: str, alias_scopes: _AliasScopes) -> str | None:
    for aliases in reversed(alias_scopes):
        if name in aliases:
            return aliases[name]
    return name


def _apply_alias(call_name: str, alias_scopes: _AliasScopes) -> str | None:
    head, *tail = call_name.split(".")
    resolved_head = _resolve_alias(head, alias_scopes)
    if resolved_head is None:
        return None
    if not tail:
        return resolved_head
    return ".".join([resolved_head, *tail])


def _resolve_getattr_call_name(node: ast.AST, alias_scopes: _AliasScopes) -> str | None:
    # Only literal-string attribute names are resolved. Payloads that build the
    # attribute name at runtime (``getattr(os, "sys" + "tem")``) need constant
    # folding we deliberately do not perform here — the complexity is not
    # worth chasing every string-arithmetic trick, and such payloads typically
    # still trip pickle or runtime detectors elsewhere in the pipeline.
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
    if resolved_target_root is None:
        return None
    return f"{resolved_target_root}.{attr_name_node.value}"


def _resolve_static_reference_name(node: ast.AST, alias_scopes: _AliasScopes) -> str | None:
    call_name = _resolve_call_name(node)
    if call_name is not None:
        return _apply_alias(call_name, alias_scopes)
    return _resolve_getattr_call_name(node, alias_scopes)


def _is_high_risk_python_call_name(name: str) -> bool:
    return name in _HIGH_RISK_PYTHON_CALLS or name.startswith("subprocess.")


def _wildcard_import_aliases(module: str) -> Iterator[tuple[str, str]]:
    prefix = f"{module}."
    for call_name in sorted(_HIGH_RISK_PYTHON_CALLS):
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
    def __init__(self) -> None:
        self.alias_scopes: _AliasScopes = [{}]
        self.risky_calls: set[str] = set()

    def _record_import(self, alias: ast.alias, import_name: str) -> None:
        self.alias_scopes[-1][alias.asname or alias.name] = import_name

    def _bind_name(self, name: str, resolved_name: str | None) -> None:
        self.alias_scopes[-1][name] = resolved_name

    def _bind_target_to_value(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self._bind_name(target.id, _resolve_static_reference_name(value, self.alias_scopes))
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
                _resolve_static_reference_name(default, self.alias_scopes) if default is not None else None,
            )
        for arg, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True):
            self._bind_name(
                arg.arg,
                _resolve_static_reference_name(default, self.alias_scopes) if default is not None else None,
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
                for local_name, import_name in _wildcard_import_aliases(node.module):
                    self._bind_name(local_name, import_name)
                continue
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
        self.alias_scopes.append({})
        try:
            self._bind_arguments(node.args)
            for statement in node.body:
                self.visit(statement)
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
        self._visit_child_scope(node.body)
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

    def _visit_loop(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        self._shadow_binding_target(node.target)
        self.visit(node.target)
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)

    def visit_For(self, node: ast.For) -> None:
        self._visit_loop(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_loop(node)

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
        resolved_name = _resolve_static_reference_name(node.func, self.alias_scopes)
        if resolved_name is not None and _is_high_risk_python_call_name(resolved_name):
            self.risky_calls.add(resolved_name)
        self.generic_visit(node)


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

    visitor = _HighRiskPythonCallVisitor()
    visitor.visit(tree)
    return {
        HighRiskPythonCall(name=name, rule_code=_rule_code_for_high_risk_call(name)) for name in visitor.risky_calls
    }


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

    if is_executable_archive_member_name(normalized_lower):
        result.add_check(
            name=_EXECUTABLE_MEMBER_CHECK_NAME,
            passed=False,
            message=f"Executable file found in {archive_kind} archive: {member_name}",
            severity=IssueSeverity.WARNING,
            location=location,
            details={"entry": member_name},
        )
