# New Scanner Quickstart (Security-First)

Use this checklist to add a new scanner safely and consistently.

## 1. Define scope before coding

- Identify exact file formats/extensions.
- Document the concrete security risks you are detecting (CVE, known exploit class, or clearly documented abuse pattern).
- Decide whether dependencies are optional and how scanner behavior degrades when missing.

Reference: `docs/agents/architecture.md`

## 2. Implement scanner class

Create `modelaudit/scanners/<format>_scanner.py` with:

- `name`, `description`, and `supported_extensions`
- `can_handle()` that is strict and deterministic
- `scan()` that uses `result.add_check(...)` with clear severity and rationale
- Path/size validation via base helpers before heavy parsing

Skeleton:

```python
from __future__ import annotations

from typing import Any, ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult


class ExampleScanner(BaseScanner):
    name = "example"
    description = "Scans Example model artifacts for security issues"
    supported_extensions: ClassVar[list[str]] = [".example"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        # extension + minimal signature checks
        ...

    def scan(self, path: str) -> ScanResult:
        path_check = self._check_path(path)
        if path_check:
            return path_check

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        # Add checks here
        result.finish(success=not result.has_errors)
        return result
```

## 3. Register the scanner

Update `modelaudit/scanners/__init__.py` in `ScannerRegistry._init_registry`:

- Add module/class metadata
- Set priority and extensions carefully
- Declare dependency names for load-time diagnostics
- Add class mapping in `__getattr__` if needed

## 4. Dependency handling rules

- Optional deps must fail gracefully with actionable messages.
- Never crash import-time for missing optional packages.
- If adding a new dependency, update `pyproject.toml` extras and justify it in PR notes.

## 5. Required tests

Add focused tests under `tests/`:

- Safe/benign sample: scanner passes expected checks
- Malicious sample: scanner emits expected findings and severities
- Corrupt input: parser errors are handled cleanly
- Missing dependency path (if optional)
- Regression tests for edge cases and previously reported bypasses

## 6. Validation before PR

```bash
uv run ruff format modelaudit/ tests/
uv run ruff check --fix modelaudit/ tests/
uv run mypy modelaudit/
uv run pytest -n auto -m "not slow and not integration" --maxfail=1
```

## 7. PR checklist

- Scanner implementation + tests are included
- Registry wiring and dependency metadata are correct
- User-facing docs updated if behavior is visible to end users
- No security checks were downgraded without explicit rationale
