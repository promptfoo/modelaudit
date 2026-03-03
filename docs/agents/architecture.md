# Scanner Architecture

## Core Components

- `cli.py`: Click-based CLI interface
- `core.py`: Main scanning logic and file traversal
- `risk_scoring.py`: Normalizes issues to 0.0-1.0 risk scores
- `scanners/`: Format-specific scanner implementations
- `utils/filetype.py`: File type detection utilities

## Scanner System

All scanners inherit from `BaseScanner` in `modelaudit/scanners/base.py`:

```python
from .base import BaseScanner, IssueSeverity, ScanResult

class MyScanner(BaseScanner):
    name = "my_scanner"  # Unique identifier
    description = "Scans my format for security issues"
    supported_extensions = [".myformat"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Return True if this scanner can handle the file."""
        return path.lower().endswith(tuple(cls.supported_extensions))

    def scan(self, path: str) -> ScanResult:
        """Scan the file and return results."""
        result = self._create_result()
        # Scanning logic here
        result.finish(success=not result.has_errors)
        return result
```

## Scanner Registration

Scanners are registered lazily via `ScannerRegistry` in `modelaudit/scanners/__init__.py`. Add to `_scanners` dict in `ScannerRegistry._init_registry`:

```python
self._scanners["my_scanner"] = {
    "module": "modelaudit.scanners.my_scanner",
    "class": "MyScanner",
    "description": "Scans My format",
    "extensions": [".my"],
    "priority": 10,
    "dependencies": [],
    "numpy_sensitive": False,
}
```

## Issue Reporting

Use `ScanResult` and `Issue` classes for consistent reporting:

```python
# Report security issues (failures)
result.add_check(
    name="Malicious Code Detection",
    passed=False,
    message="Detected malicious code execution",
    severity=IssueSeverity.CRITICAL,
    location=path,
    details={"pattern": "os.system", "position": 123}
)

# Report successful checks (informational)
result.add_check(
    name="Format Detection",
    passed=True,
    message="Valid model format detected",
    severity=IssueSeverity.INFO,
    details={"format": "pytorch"}
)
```

## Issue Severity Levels

- `DEBUG`: Diagnostic information
- `INFO`: Informational messages
- `WARNING`: Potential issues
- `CRITICAL`: Security vulnerabilities

## Key Files

- `modelaudit/scanners/base.py`: Scanner interface and base classes
- `modelaudit/core.py`: Main scanning orchestration logic
- `modelaudit/cli.py`: Command-line interface
- `pyproject.toml`: Dependencies and project configuration
- `tests/conftest.py`: Test configuration and fixtures
