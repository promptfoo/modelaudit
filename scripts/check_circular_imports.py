#!/usr/bin/env python3
"""Check for circular imports between base.py and core.py modules."""

import ast
import importlib.util
import sys
from pathlib import Path


def find_module_path(name: str) -> Path | None:
    """Find the file path for a given module name."""
    spec = importlib.util.find_spec(name)
    return Path(spec.origin) if spec and spec.origin else None


def module_imports_target(path: Path | None, targets: set[str]) -> bool:
    """Check if a module file imports any of the target modules."""
    if not path or not path.exists():
        return False

    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as e:
        print(f"⚠️  Warning: Could not parse {path}: {e}")
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in targets:
                    return True
        elif isinstance(node, ast.ImportFrom):
            # Absolute imports
            if node.module and node.module in targets:
                return True
            # Relative imports (e.g., from ..core import ...)
            # Normalize relative by best-effort suffix match
            if node.module and any(node.module.endswith(t.split(".", 1)[-1]) for t in targets):
                return True
    return False


def detect_circular_imports() -> list[str]:
    """Detect all potential circular import patterns in the modelaudit package."""
    violations = []

    # Define key modules that should not have circular dependencies
    key_modules = {
        "modelaudit.scanners.base": "scanners/base.py",
        "modelaudit.core": "core.py",
        "modelaudit.utils.result_conversion": "utils/result_conversion.py",
        "modelaudit.utils.advanced_file_handler": "utils/advanced_file_handler.py",
        "modelaudit.utils.large_file_handler": "utils/large_file_handler.py",
    }

    # Define prohibited circular patterns
    prohibited_patterns = [
        # Base scanner should not import from core (the original issue)
        ("modelaudit.scanners.base", "modelaudit.core", "Base scanner importing core creates circular dependency"),
        # Utilities should not import from core (would create cycles through scanners)
        (
            "modelaudit.utils.result_conversion",
            "modelaudit.core",
            "Result conversion utility importing core creates cycles",
        ),
        (
            "modelaudit.utils.advanced_file_handler",
            "modelaudit.core",
            "Advanced file handler importing core creates cycles",
        ),
        (
            "modelaudit.utils.large_file_handler",
            "modelaudit.core",
            "Large file handler importing core creates cycles",
        ),
        # Core should not import utilities that import scanners.base (would create indirect cycles)
        # This is more complex to detect, so we focus on the direct patterns above
    ]

    for source_module, target_module, description in prohibited_patterns:
        source_path = find_module_path(source_module)
        if module_imports_target(source_path, {target_module}):
            source_name = key_modules.get(source_module, source_module)
            target_name = key_modules.get(target_module, target_module)
            violations.append(f"❌ Circular import: {source_name} imports {target_name} - {description}")

    return violations


def main():
    """Main function to check for circular imports."""
    print("🔍 Checking for circular imports...")

    # Basic imports test
    try:
        import modelaudit  # noqa: F401
        from modelaudit.core import scan_file  # noqa: F401
        from modelaudit.scanners.base import BaseScanner, ScanResult  # noqa: F401
        from modelaudit.utils.result_conversion import scan_result_from_dict  # noqa: F401

        print("✅ All imports successful")
    except Exception as e:
        print(f"❌ Import failed: {e}")
        sys.exit(1)

    # Detect circular import violations
    violations = detect_circular_imports()

    if violations:
        print("\n".join(violations))
        print(f"\n❌ Found {len(violations)} circular import violation(s)")
        sys.exit(1)

    print("✅ No circular imports detected")


if __name__ == "__main__":
    main()
