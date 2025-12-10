# Testing Guidelines

## Core Requirements

- **Tests must run fast** - Aim for < 1 second per test
- **Tests run in any order** - Uses pytest-randomly
- **Use mocks/fixtures** for expensive operations
- **Tests are independent** - No shared state between tests
- **NumPy compatibility** - Tests run against both NumPy 1.x and 2.x in CI

## Test Markers

```python
@pytest.mark.slow         # Long-running tests (skipped in fast mode)
@pytest.mark.integration  # Integration tests
@pytest.mark.performance  # Performance benchmarks
@pytest.mark.unit         # Unit tests (default)
```

## Test Structure

- **One test file per scanner**: `tests/test_{scanner_name}.py`
- **Integration tests**: `tests/test_integration.py`
- **CLI tests**: `tests/test_cli.py`

## Test Patterns

```python
from pathlib import Path
import pytest
from modelaudit.scanners.my_scanner import MyScanner

def test_scanner_safe_file(tmp_path: Path) -> None:
    """Test scanner with safe file."""
    test_file = tmp_path / "safe.myformat"
    test_file.write_bytes(b"safe content")

    scanner = MyScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True
    assert not result.has_errors

def test_scanner_malicious_file(tmp_path: Path) -> None:
    """Test scanner with malicious file."""
    malicious_file = tmp_path / "malicious.myformat"
    malicious_file.write_bytes(b"malicious content")

    scanner = MyScanner()
    result = scanner.scan(str(malicious_file))

    assert result.has_errors
    assert any("malicious" in issue.message.lower() for issue in result.issues)
```

## Running Tests

```bash
# Fast tests (recommended for development)
rye run pytest -n auto -m "not slow and not integration"

# Fast tests with coverage (CI only)
rye run pytest -n auto -m "not slow and not integration" --cov=modelaudit

# Specific scanner tests
rye run pytest tests/test_pickle_scanner.py -v

# Run only last failed tests
rye run pytest --lf -v

# Fail-fast mode
rye run pytest -x --maxfail=1 -n auto
```

## Smart Test Targeting

Target tests related to your changes:

```bash
# Scanner changes
rye run pytest tests/test_*scanner*.py -k "not slow" -v

# Filetype/core changes
rye run pytest tests/test_filetype.py tests/test_core*.py -v

# Utility changes
rye run pytest tests/test_utils/ -v
```
