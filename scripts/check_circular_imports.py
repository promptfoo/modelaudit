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
    
    tree = ast.parse(path.read_text(encoding='utf-8'))
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
            if node.module and any(node.module.endswith(t.split('.', 1)[-1]) for t in targets):
                return True
    return False


def main():
    """Main function to check for circular imports."""
    print('🔍 Checking for circular imports...')

    # Basic imports test
    try:
        import modelaudit  # noqa: F401
        from modelaudit.scanners.base import BaseScanner, ScanResult  # noqa: F401
        from modelaudit.core import scan_file  # noqa: F401
        from modelaudit.utils.result_conversion import scan_result_from_dict  # noqa: F401
        print('✅ All imports successful')
    except Exception as e:
        print(f'❌ Import failed: {e}')
        sys.exit(1)

    # Find module paths
    base_path = find_module_path('modelaudit.scanners.base')
    core_path = find_module_path('modelaudit.core')

    # Only check the problematic direction: base -> core
    # (core -> base is legitimate and expected)
    if module_imports_target(base_path, {'modelaudit.core'}):
        print('❌ Circular import detected: scanners/base.py imports from core.py')
        sys.exit(1)

    print('✅ No circular imports detected')


if __name__ == '__main__':
    main()