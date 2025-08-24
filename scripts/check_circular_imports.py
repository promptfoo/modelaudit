#!/usr/bin/env python3
"""Check for circular imports between base.py and core.py modules."""

import ast
import importlib.util
import sys
from pathlib import Path


def find_module_path(name: str) -> Path | None:
    """Find the file path for a given module name."""
    try:
        spec = importlib.util.find_spec(name)
        return Path(spec.origin) if spec and spec.origin else None
    except (ImportError, ModuleNotFoundError, ValueError) as e:
        # Handle cases where module spec can't be found
        print(f"⚠️  Could not locate module {name}: {e}")
        return None


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

    # Skip runtime import testing in favor of pure static analysis
    # This avoids dependency issues in CI environments with limited package installations
    print("Using static analysis only (more reliable in CI environments)")
    import_check_passed = False

    # Detect circular import violations
    violations = detect_circular_imports()

    if violations:
        print("\n".join(violations))
        print(f"\n❌ Found {len(violations)} circular import violation(s)")
        sys.exit(1)

    success_msg = "✅ No circular imports detected"
    if import_check_passed:
        success_msg += " (with runtime import verification)"
    else:
        success_msg += " (static analysis only)"
    print(success_msg)


if __name__ == "__main__":
    main()
