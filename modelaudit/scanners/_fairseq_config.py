"""Static checks for fairseq configuration expressions."""

import ast
from collections.abc import Callable
from typing import Any

from .base import IssueSeverity, ScanResult


def check_fairseq_expressions(
    content: Any, result: ScanResult, location: str | None, check_timeout: Callable[[], bool]
) -> None:
    """Find executable expressions in fairseq's evaluated convolution config."""
    pending = [("", content)]
    visited: set[int] = set()
    safe_nodes = (
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
    )
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
                try:
                    expression = ast.parse(item, mode="eval")
                except (SyntaxError, ValueError, RecursionError):
                    continue
                if any(not isinstance(node, safe_nodes) for node in ast.walk(expression)):
                    result.add_check(
                        name="fairseq Configuration Code Injection",
                        passed=False,
                        message=f"Executable Python expression in fairseq configuration field {path}",
                        severity=IssueSeverity.CRITICAL,
                        location=location,
                        details={"key": path, "expression": item, "advisory": "ZDI-26-922"},
                        why="Affected fairseq models evaluate conv_feature_layers as Python code when loaded.",
                        rule_code="S104",
                    )
            elif isinstance(item, (dict, list)):
                pending.append((path, item))
