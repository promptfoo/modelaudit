# AGENTS.md - AI Agent Guide for ModelAudit

This file provides comprehensive guidance for AI agents working with the ModelAudit codebase - a security scanner for AI/ML model files.

## 🎯 Project Overview

ModelAudit is a Python security scanner that detects malicious code, backdoors, and security risks in ML model files. It supports multiple formats (PyTorch, TensorFlow, Keras, SafeTensors, Pickle, ZIP) and provides both CLI and programmatic interfaces.

**Key Security Focus:**

- Dangerous code execution patterns
- Suspicious opcodes in pickle files
- Malicious configurations in model files
- Blacklisted model names and patterns
- Weight distribution anomalies

## 📁 Project Structure

```
modelaudit/
├── modelaudit/                 # Main package
│   ├── scanners/              # Core scanner implementations
│   │   ├── base.py           # Abstract base scanner class
│   │   ├── pickle_scanner.py  # Pickle security scanner
│   │   ├── pytorch_zip_scanner.py  # PyTorch model scanner
│   │   ├── tf_savedmodel_scanner.py  # TensorFlow scanner
│   │   ├── keras_h5_scanner.py     # Keras H5 scanner
│   │   ├── safetensors_scanner.py  # SafeTensors scanner
│   │   ├── manifest_scanner.py     # Config/manifest scanner
│   │   ├── weight_distribution_scanner.py  # Weight anomaly detection
│   │   └── zip_scanner.py          # Generic ZIP scanner
│   ├── utils/                 # Utility modules
│   │   ├── filetype.py       # File format detection
│   │   └── __init__.py
│   ├── name_policies/         # Model name blacklist policies
│   ├── cli.py                # Command-line interface
│   ├── core.py               # Core scanning logic
│   └── __init__.py
├── tests/                     # Test suite
│   ├── test_*_scanner.py     # Scanner-specific tests
│   ├── test_integration.py   # Integration tests
│   ├── test_cli.py          # CLI tests
│   └── conftest.py          # pytest configuration
├── pyproject.toml           # Rye configuration
├── README.md                # Project documentation
└── CLAUDE.md               # Claude-specific guidance
```

## 🔧 Development Conventions

### Branching & Changelog

- **Each feature branch should add exactly one entry to CHANGELOG.md** in the [Unreleased] section following Keep a Changelog format
- Use conventional commit format (feat:, fix:, docs:, chore:, test:, refactor:)
- Never commit directly to main branch

### Code Style & Standards

**Python Version:** 3.9+ (supports 3.9, 3.10, 3.11, 3.12, 3.13)

**Code Quality Tools:**

- **Ruff**: Ultra-fast linter and formatter (replaces Black, isort, flake8)
- **MyPy**: Static type checking
- **pytest**: Testing framework with coverage

**Code Quality Standards (matches CI workflow):**

```bash
# PRE-COMMIT WORKFLOW (development - format equivalents):
rye run ruff format modelaudit/ tests/           # Format code and tests
rye run ruff check --fix modelaudit/ tests/      # Lint and fix issues
rye run ruff check --fix --select I modelaudit/ tests/  # Fix import organization
rye run mypy modelaudit/ tests/                  # Type check (both prod and tests)
rye run pytest -n auto -m "not slow and not integration and not performance" --cov=modelaudit --tb=short  # Fast tests
rye run pytest -n auto -m "slow or integration" --tb=short  # Slow/integration tests

# CI VERIFICATION COMMANDS (read-only, matches test.yml):
rye run ruff check modelaudit/ tests/            # Lint check
rye run ruff check --select I modelaudit/ tests/ # Import organization check
rye run ruff format --check modelaudit/ tests/   # Format verification
rye run mypy modelaudit/ tests/                  # Type checking
rye run pytest -n auto -m "not slow and not integration and not performance" --cov=modelaudit --tb=short  # Fast tests
rye run pytest -n auto -m "slow or integration" --tb=short  # Slow/integration tests (main branch only in CI)
```

### Naming Conventions

- **Classes**: PascalCase (e.g., `PickleScanner`, `BaseScanner`)
- **Functions/Variables**: snake_case (e.g., `scan_model`, `file_path`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `SUSPICIOUS_GLOBALS`, `DANGEROUS_OPCODES`)
- **Private methods**: Leading underscore (e.g., `_check_path`, `_create_result`)

### Type Hints

Always use type hints for function parameters and return values:

```python
def scan(self, path: str) -> ScanResult:
    """Scan a model file."""
    pass

def can_handle(cls, path: str) -> bool:
    """Check if scanner can handle this file."""
    return True
```

## 🛡️ Scanner Architecture

### Creating New Scanners

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
        # Implementation here
        pass

    def scan(self, path: str) -> ScanResult:
        """Scan the file and return results."""
        result = self._create_result()
        # Scanning logic here
        result.finish(success=not result.has_errors)
        return result
```

### Scanner Registration

Scanners are registered lazily via `ScannerRegistry` in
`modelaudit/scanners/__init__.py`. `SCANNER_REGISTRY` exposes a lazy list of
available scanner classes. To register a new scanner, add its metadata to the
`_scanners` dictionary inside `ScannerRegistry._init_registry`:

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

After adding the entry, the scanner will appear in `SCANNER_REGISTRY` when it is
first accessed.

### Issue Reporting

Use the `ScanResult` and `Issue` classes for consistent reporting:

```python
# Report security issues
result.add_issue(
    "Detected malicious code execution",
    severity=IssueSeverity.CRITICAL,
    location=path,
    details={"pattern": "os.system", "position": 123}
)

# Valid severity levels: DEBUG, INFO, WARNING, CRITICAL
```

## 🧪 Testing Guidelines

### Test Structure

- **One test file per scanner**: `tests/test_{scanner_name}.py`
- **Integration tests**: `tests/test_integration.py`
- **CLI tests**: `tests/test_cli.py`

### Test Patterns

```python
from pathlib import Path
import pytest
from modelaudit.scanners.my_scanner import MyScanner

def test_my_scanner_safe_file(tmp_path: Path) -> None:
    """Test scanner with safe file."""
    # Create test file
    test_file = tmp_path / "safe.myformat"
    test_file.write_bytes(b"safe content")

    # Run scanner
    scanner = MyScanner()
    result = scanner.scan(str(test_file))

    # Assert results
    assert result.success is True
    assert not result.has_errors

def test_my_scanner_malicious_file(tmp_path: Path) -> None:
    """Test scanner with malicious file."""
    # Create malicious test file
    malicious_file = tmp_path / "malicious.myformat"
    malicious_file.write_bytes(b"malicious content")

    # Run scanner
    scanner = MyScanner()
    result = scanner.scan(str(malicious_file))

    # Assert malicious content detected
    assert result.has_errors
    assert any("malicious" in issue.message.lower() for issue in result.issues)
```

### Running Tests

```bash
# Run fast tests (matches CI workflow - parallel execution, excludes slow/integration/performance tests)
rye run pytest -n auto -m "not slow and not integration and not performance" --cov=modelaudit --tb=short

# Run slow/integration tests (matches CI workflow - usually main branch only)
rye run pytest -n auto -m "slow or integration" --tb=short

# Run all tests (not recommended for regular development)
rye run pytest

# Run specific test file
rye run pytest tests/test_my_scanner.py -v

# Run with coverage (already included in fast tests command above)
rye run pytest --cov=modelaudit

# Run tests for specific Python versions (matches CI matrix: 3.9, 3.10, 3.11, 3.12)
rye sync --features all  # Install all dependencies first
rye pin 3.11             # Pin to specific version (example)
rye run pytest -n auto -m "not slow and not integration and not performance" --cov=modelaudit --tb=short
```

## 📦 Dependencies & Installation

### Development Setup

```bash
# Clone and setup
git clone https://github.com/promptfoo/modelaudit.git
cd modelaudit

# Install with Rye (recommended) - matches CI workflow
rye sync --features all  # All optional dependencies for comprehensive testing
rye sync                 # Basic dependencies only

# Or with pip (alternative)
pip install -e .[all]    # Install in development mode with all extras
pip install -e .         # Basic installation
```

### Optional Dependencies

The project uses optional dependencies for specific scanners:

- `tensorflow`: TensorFlow SavedModel scanning
- `h5`: Keras H5 model scanning (h5py)
- `pytorch`: PyTorch model scanning (torch)
- `yaml`: YAML manifest scanning (pyyaml)
- `safetensors`: SafeTensors model scanning
- `onnx`: ONNX model scanning
- `dill`: Enhanced pickle support with security validation
- `joblib`: Joblib model scanning with scikit-learn integration
- `flax`: Flax msgpack scanning
- `tflite`: TensorFlow Lite model scanning
- `all`: All of the above dependencies

Install specific extras as needed:

```bash
# With pip
pip install modelaudit[tensorflow,pytorch,h5]

# With rye (development)
rye sync --features="tensorflow pytorch h5"
```

Always test that scanners gracefully handle missing optional dependencies.

## 🔍 Security Detection Patterns

### Common Suspicious Patterns

```python
# Dangerous imports to detect
SUSPICIOUS_GLOBALS = {
    "os": "*",
    "subprocess": "*",
    "eval": "*",
    "exec": "*",
    "__import__": "*"
}

# Dangerous pickle opcodes
DANGEROUS_OPCODES = [
    "REDUCE", "INST", "OBJ", "NEWOBJ", "STACK_GLOBAL"
]

# Suspicious string patterns
SUSPICIOUS_PATTERNS = [
    r"os\.system",
    r"subprocess\.",
    r"eval\(",
    r"exec\(",
    r"__import__"
]
```

### ML Context Detection

The codebase includes smart detection to reduce false positives in ML contexts:

```python
# ML-safe patterns that shouldn't trigger alerts
ML_SAFE_GLOBALS = {
    "torch": ["*"],
    "numpy": ["*"],
    "transformers": ["*"],
    "sklearn": ["*"]
}
```

## 🚀 CLI Usage

### Basic Commands

```bash
# Scan single file
modelaudit scan model.pkl

# Scan directory
modelaudit scan ./models/

# Export to JSON
modelaudit scan model.pkl --format json --output results.json

# With custom blacklist
modelaudit scan model.pkl --blacklist "unsafe_model"

# Verbose output
modelaudit scan model.pkl --verbose
```

### Exit Codes

- **0**: No security issues found
- **1**: Security issues detected (scan succeeded)
- **2**: Scan errors occurred (file not found, etc.)

## 🎯 AI Agent Guidelines

### When Modifying Scanners

1. **Always preserve security focus** - Don't weaken detection capabilities
2. **Test with both safe and malicious samples**
3. **Consider ML context** - Avoid false positives in legitimate ML usage
4. **Follow the scanner pattern** - Use `BaseScanner` interface
5. **Add comprehensive tests** - Include edge cases and error conditions

### When Adding Features

1. **Check optional dependencies** - Handle gracefully when missing
2. **Update `SCANNER_REGISTRY`** if adding new scanners
3. **Follow existing code patterns** and style
4. **Add appropriate documentation**
5. **Consider CI/CD impact** - Ensure tests pass across Python versions

### When Debugging Issues

1. **Check file format detection** in `utils/filetype.py`
2. **Verify scanner selection** logic in core scanning
3. **Review issue severity levels** and reporting
4. **Test with various file formats** and edge cases
5. **Use verbose mode** for detailed logging

## 📋 Pull Request Guidelines

When contributing code:

1. **Follow conventional commits**: `feat:`, `fix:`, `docs:`, etc.
2. **All tests must pass** across Python 3.9-3.13
3. **Code must be formatted** with Ruff
4. **Type checking must pass** with MyPy
5. **Keep PRs focused** on single concerns
6. **Include tests** for new functionality
7. **Update documentation** as needed

### Pre-commit Checklist

```bash
# Run before every commit (matches CI workflow with format equivalents):
rye run ruff format modelaudit/ tests/           # Format code and tests
rye run ruff check --fix modelaudit/ tests/      # Lint and fix issues
rye run ruff check --fix --select I modelaudit/ tests/  # Fix import organization
rye run mypy modelaudit/ tests/                  # Type check (both prod and tests)
rye run pytest -n auto -m "not slow and not integration and not performance" --cov=modelaudit --tb=short  # Fast tests
```

## 🔗 Key Files for AI Agents

- **`modelaudit/scanners/base.py`**: Scanner interface and base classes
- **`modelaudit/core.py`**: Main scanning orchestration logic
- **`modelaudit/cli.py`**: Command-line interface implementation
- **`pyproject.toml`**: Dependencies and project configuration
- **`tests/conftest.py`**: Test configuration and fixtures

Understanding these files is crucial for effective contributions to the ModelAudit codebase.

## 🧰 Non-Interactive Commands

To keep automation reliable and prevent stalls:

- Always run commands non-interactively: supply flags to avoid editors/prompts (e.g., `git merge --no-edit`, `git commit -m`, `gh pr checkout <n>`).
- Run one command per invocation: avoid long `&&` chains or complex pipelines; check each command’s result before the next.
- Keep merges clean: `git fetch origin` then `git merge --no-edit origin/main` on the PR branch before fixes.
- Resolve conflicts deterministically: edit files, run `ruff check` and `ruff format` on specific paths you touched, then commit with a clear message.
- Prevent lockups: if `/.git/index.lock` appears and no other git process is running, remove it (`rm .git/index.lock`) before continuing.
- Be selective with staging: only `git add` intended paths; avoid committing local artifacts (e.g., `_temp_files/`).
- Validate locally: run `ruff check` and `ruff format --check` on targeted files; run the minimal pytest matrix relevant to your changes where feasible.
- Trigger CI safely: prefer a minimal “ci: trigger” empty commit or use `gh run rerun <run-id>` rather than force-pushing.
