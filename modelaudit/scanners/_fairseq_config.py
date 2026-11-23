"""Static checks for fairseq configuration expressions."""

import ast
import re
from collections.abc import Callable
from typing import Any

from modelaudit.scanner_results import mark_inconclusive_scan_result

from .base import IssueSeverity, ScanResult


def _resolve_expression(content: Any, expression: str, check_timeout: Callable[[], bool]) -> str:
    """Expand bounded scalar references without running OmegaConf resolvers."""
    remaining = 256
    max_length = 65536

    def expand(value: str, active: tuple[str, ...]) -> str:
        nonlocal remaining
        if len(value) > max_length or len(active) > 32:
            raise ValueError("interpolation size or depth limit exceeded")
        pieces: list[str] = []
        length = 0
        offset = 0
        for match in re.finditer(r"\$\{([^{}]+)\}", value):
            reference = match[1]
            if reference in active or ":" in reference:
                raise ValueError("cyclic or unsupported interpolation")
            selected = content
            for part in reference.split("."):
                check_timeout()
                remaining -= 1
                if remaining < 0:
                    raise ValueError("interpolation lookup limit exceeded")
                if isinstance(selected, dict) and part in selected:
                    selected = selected[part]
                else:
                    raise ValueError("interpolation does not select a same-document scalar")
            if type(selected) not in (str, int, float, bool, type(None)):
                raise ValueError("interpolation does not select a same-document scalar")
            replacement = expand(str(selected), (*active, reference))
            prefix = value[offset : match.start()]
            if "${" in prefix:
                raise ValueError("unsupported interpolation syntax")
            length += len(prefix) + len(replacement)
            if length > max_length:
                raise ValueError("interpolation size limit exceeded")
            pieces.extend((prefix, replacement))
            offset = match.end()
        suffix = value[offset:]
        if "${" in suffix:
            raise ValueError("unsupported interpolation syntax")
        if length + len(suffix) > max_length:
            raise ValueError("interpolation size limit exceeded")
        expanded = "".join((*pieces, suffix))
        if "${" in expanded:
            raise ValueError("expansion produces another interpolation")
        return expanded

    return expand(expression, ())


def _is_executable(expression: str) -> bool:
    try:
        tree = ast.parse(expression.lstrip(" \t"), mode="eval")
    except (SyntaxError, ValueError, RecursionError):
        return False
    return any(
        not isinstance(
            node,
            (
                ast.Expression,
                ast.List,
                ast.Tuple,
                ast.Constant,
                ast.BinOp,
                ast.UnaryOp,
                ast.Load,
                ast.Add,
                ast.Sub,
                ast.Mult,
                ast.UAdd,
                ast.USub,
            ),
        )
        for node in ast.walk(tree)
    )


def check_fairseq_expressions(
    content: Any, result: ScanResult, location: str | None, check_timeout: Callable[[], bool]
) -> None:
    """Find executable expressions in fairseq's evaluated convolution config."""
    pending = [("", content)]
    visited: set[int] = set()
    while pending:
        check_timeout()
        prefix, value = pending.pop()
        if not isinstance(value, (dict, list)) or id(value) in visited:
            continue
        visited.add(id(value))
        entries = value.items() if isinstance(value, dict) else enumerate(value)
        for key, item in entries:
            path = f"{prefix}.{key}" if prefix else str(key)
            if key == "conv_feature_layers" and isinstance(item, str):
                expression = item
                executable = _is_executable(item)
                # Keep a known direct finding even if an external resolver cannot be inspected.
                if not executable and "${" in item:
                    try:
                        expression = _resolve_expression(content, item, check_timeout)
                    except ValueError as error:
                        reason = "fairseq_config_interpolation_incomplete"
                        mark_inconclusive_scan_result(result, reason)
                        result.add_check(
                            name="fairseq Configuration Coverage",
                            passed=False,
                            message=f"fairseq configuration analysis incomplete at {path}: {error}",
                            severity=IssueSeverity.INFO,
                            location=location,
                            details={"key": path, "expression": item, "analysis_incomplete": True, "reason": reason},
                            rule_code="S902",
                        )
                        continue
                    executable = _is_executable(expression)
                if executable:
                    details = {"key": path, "expression": item, "advisory": "ZDI-26-922"}
                    if expression != item:
                        details["resolved_expression"] = expression
                    result.add_check(
                        name="fairseq Configuration Code Injection",
                        passed=False,
                        message=f"Executable Python expression in fairseq configuration field {path}",
                        severity=IssueSeverity.CRITICAL,
                        location=location,
                        details=details,
                        why="Affected fairseq models evaluate conv_feature_layers as Python code when loaded.",
                        rule_code="S104",
                    )
            elif isinstance(item, (dict, list)):
                pending.append((path, item))
