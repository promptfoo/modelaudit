#!/usr/bin/env python3
"""Minimal circular import check for CI environments."""

import ast
import sys
from pathlib import Path


def check_base_imports_core() -> bool:
    """Check if scanners/base.py imports from core.py (the main issue we're preventing)."""
    base_file = Path("modelaudit/scanners/base.py")

    if not base_file.exists():
        print(f"❌ Could not find {base_file}")
        return False

    try:
        content = base_file.read_text(encoding="utf-8")
        tree = ast.parse(content)
    except Exception as e:
        print(f"❌ Could not parse {base_file}: {e}")
        return False

    # Check for imports of core module
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "modelaudit.core":
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module == "modelaudit.core":
                return True
            # Relative imports
            if node.module and node.module in ("..core", ".core"):
                return True

    return False


def main():
    """Main function."""
    print("🔍 Checking for circular imports (minimal check)...")

    if check_base_imports_core():
        print("❌ Circular import detected: scanners/base.py imports from core.py")
        sys.exit(1)

    print("✅ No circular imports detected")


if __name__ == "__main__":
    main()
