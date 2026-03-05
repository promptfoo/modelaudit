"""Consistency checks for scanner rule code literals."""

import ast
from pathlib import Path

from modelaudit.rules import RuleRegistry

SCANNERS_DIR = Path(__file__).resolve().parents[2] / "modelaudit" / "scanners"


def _extract_literal_rule_codes(path: Path) -> set[str]:
    """Extract literal `rule_code=\"S...\"` values from scanner source."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    codes: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue

        for keyword in node.keywords:
            if keyword.arg != "rule_code":
                continue
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                normalized = keyword.value.value.strip().upper()
                if normalized.startswith("S"):
                    codes.add(normalized)

    return codes


def test_scanner_literal_rule_codes_are_registered() -> None:
    """All literal scanner rule codes should exist in RuleRegistry."""
    known_codes = set(RuleRegistry.get_all_rules().keys())
    unknown_by_file: dict[str, list[str]] = {}

    for scanner_file in SCANNERS_DIR.glob("*.py"):
        if scanner_file.name == "__init__.py":
            continue

        unknown_codes = sorted(code for code in _extract_literal_rule_codes(scanner_file) if code not in known_codes)
        if unknown_codes:
            unknown_by_file[scanner_file.name] = unknown_codes

    assert not unknown_by_file, f"Scanner files contain unknown rule code literals: {unknown_by_file}"
