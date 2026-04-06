# Scanner Architecture

## Core Components

- `cli.py`: Click-based CLI interface
- `core.py`: Main scanning logic and file traversal
- `metadata_extractor.py`: Metadata extraction command backend (`modelaudit metadata`)
- `scanner_results.py`: Leaf result/check/issue contracts re-exported by `scanners/base.py`
- `scanner_registry_metadata.py`: Static scanner metadata consumed by registry loading and extension utilities
- `scanners/`: Format-specific scanner implementations
- `utils/file/detection.py`: File type and content detection utilities
- `utils/sources/huggingface_paths.py`: Leaf HuggingFace URL/cache provenance parsing
- `version.py`: Leaf package-version lookup used by package init and telemetry

## Routing & Coverage Invariants

- Prefer trusted file structure and bounded content sniffing over extension-only routing, especially for ZIP-like containers and nested archives.
- Keep scanner routing metadata descriptor-owned in `ScannerRegistry`; header-format aliases, content-routed extensions, and lazy class exports should come from one descriptor entry, with `can_handle()` as the final content gate.
- For routing, prefiltering, or archive-recursion changes, add one malicious positive regression and one benign near-match negative regression.
- If a scanner aborts to avoid partial coverage, make the result operationally explicit (`success=False` with a clear error message) and preserve consistent exit-code and cache behavior.

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
        result = self._create_scan_result_after_preflight(path)
        if not result.success:
            return result
        # Scanning logic here
        result.finish(success=not result.has_errors)
        return result
```

## Scanner Registration

Scanners are registered lazily via `ScannerRegistry` in `modelaudit/scanners/__init__.py`. Add static metadata to `modelaudit/scanner_registry_metadata.py`:

```python
"my_scanner": {
    "module": "modelaudit.scanners.my_scanner",
    "class": "MyScanner",
    "description": "Scans My format",
    "extensions": [".my"],
    "header_formats": ["my_magic"],  # Optional aliases from detect_file_format()
    "content_routed_extensions": [".zip"],  # Optional suffixes gated by can_handle()
    "scanner_only_extensions": [".alt"],  # Optional intentional class-vs-routing differences
    "content_routed_filenames": ["readme"],  # Optional extensionless filename routes
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
- `modelaudit/scanners/<scanner>_support/`: Extracted helper modules for large scanners while preserving public `<scanner>_scanner.py` entrypoints
- `modelaudit/core.py`: Main scanning orchestration logic
- `modelaudit/cli.py`: Command-line interface
- `pyproject.toml`: Dependencies and project configuration
- `tests/conftest.py`: Test configuration and fixtures
