# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ModelAudit is a security scanner for AI/ML model files that detects potential security risks before deployment. It scans for malicious code, suspicious operations, unsafe configurations, and blacklisted model names.

## Key Commands

```bash
# Setup - Dependency Profiles
rye sync --features all        # Install all dependencies (recommended for development)
rye sync --features all-ci     # All dependencies except platform-specific (for CI)
rye sync                       # Minimal dependencies (pickle, numpy, zip)
rye sync --features tensorflow # Specific framework support
rye sync --features numpy1     # NumPy 1.x compatibility mode (when ML frameworks conflict)

# Running the scanner (scan is the default command)
rye run modelaudit model.pkl
rye run modelaudit --format json --output results.json model.pkl
# Or explicitly with scan command:
rye run modelaudit scan model.pkl

# Large Model Support (8GB+)
rye run modelaudit large_model.bin --timeout 1800  # 30 min timeout for large models
rye run modelaudit huge_model.bin --verbose  # Show progress for large files
rye run modelaudit model.bin --no-large-model-support  # Disable optimizations

# Testing (IMPORTANT: Tests should run fast!)
rye run pytest -n auto -m "not slow and not integration"  # Fast development testing (recommended)
rye run pytest -n auto                  # Run all tests with parallel execution
rye run pytest tests/test_pickle_scanner.py  # Run specific test file
rye run pytest -k "test_pickle"         # Run tests matching pattern
rye run pytest -n auto --cov=modelaudit # Full test suite with coverage

# Linting and Formatting
rye run ruff format modelaudit/ tests/   # Format code (ALWAYS run before committing)
rye run ruff check --fix modelaudit/ tests/  # Fix linting issues
rye run mypy modelaudit/                 # Type checking
npx prettier@latest --write "**/*.{md,yaml,yml,json}"  # Format markdown, YAML, JSON files

# CI Checks - ALWAYS run these before committing:
# 1. rye run ruff format modelaudit/ tests/
# 2. rye run ruff check modelaudit/ tests/  # IMPORTANT: Check without --fix first!
# 3. rye run ruff check --fix modelaudit/ tests/  # Then fix any issues
# 4. rye run mypy modelaudit/
# 5. rye run pytest -n auto -m "not slow and not integration"  # Fast tests first
# 6. npx prettier@latest --write "**/*.{md,yaml,yml,json}"
```

## Testing Requirements

- **IMPORTANT**: Unit tests should run quickly! Refactor long-running tests.
- Tests must be able to run in any order (use pytest-randomly)
- Keep test execution time minimal - aim for < 1 second per test
- Use mocks/fixtures for expensive operations
- Tests should be independent and not rely on execution order
- Test markers available: `@pytest.mark.slow`, `@pytest.mark.integration`, `@pytest.mark.performance`, `@pytest.mark.unit`
- NumPy compatibility: Tests run against both NumPy 1.x and 2.x in CI

## Architecture

### Scanner System

- All scanners inherit from `BaseScanner` in `modelaudit/scanners/base.py`
- Scanners implement `can_handle(file_path)` and `scan(file_path, timeout)` methods
- Scanner registration happens via `SCANNER_REGISTRY` in `modelaudit/scanners/__init__.py`
- Each scanner returns a `ScanResult` containing `Issue` objects

### Core Components

- `cli.py`: Click-based CLI interface
- `core.py`: Main scanning logic and file traversal
- `risk_scoring.py`: Normalizes issues to 0.0-1.0 risk scores
- `scanners/`: Format-specific scanner implementations
- `utils/filetype.py`: File type detection utilities

### Adding New Scanners

1. Create scanner class inheriting from `BaseScanner`
2. Implement `can_handle()` and `scan()` methods
3. Register in `SCANNER_REGISTRY`
4. Add tests in `tests/test_<scanner_name>.py`

### Security Detection Focus

- Dangerous imports (os, sys, subprocess, eval, exec)
- Pickle opcodes (REDUCE, INST, OBJ, NEWOBJ, STACK_GLOBAL)
- Encoded payloads (base64, hex)
- Unsafe Lambda layers (Keras/TensorFlow)
- Executable files in archives
- Blacklisted model names
- Weight distribution anomalies (outlier neurons, dissimilar weight vectors)

## Exit Codes

- 0: No security issues found
- 1: Security issues detected
- 2: Scan errors occurred

## Input Sources

ModelAudit supports multiple input sources:

- Local files and directories
- HuggingFace models: `hf://username/model` or `https://huggingface.co/username/model`
- Cloud storage: S3 (`s3://bucket/path`), GCS (`gs://bucket/path`)
- MLflow models: `models://model-name/version`
- JFrog Artifactory URLs
- DVC pointer files (`.dvc`)

## Environment Variables

- `JFROG_API_TOKEN` or `JFROG_ACCESS_TOKEN` - JFrog authentication
- `NO_COLOR` - Disable color output (follows https://no-color.org standard)
- `.env` file is automatically loaded if present

## CI/CD Integration

ModelAudit automatically adapts its output for CI environments:

- **TTY Detection**: Spinners are disabled when output is not a terminal (piped, CI, etc.)
- **Color Control**: Respects `NO_COLOR` environment variable to disable colors
- **Recommended for CI**: Use `--format json` for machine-readable output
- **Exit Codes**: 0 (no issues), 1 (issues found), 2 (scan errors)

Example CI usage:

```bash
# JSON output for parsing (recommended)
modelaudit model.pkl --format json --output results.json

# Text output with automatic CI detection
modelaudit model.pkl | tee results.txt

# Explicitly disable colors
NO_COLOR=1 modelaudit model.pkl
```

## Additional Commands

```bash
# Diagnose scanner compatibility
rye run modelaudit doctor --show-failed

# Build package
rye build

# Publishing (maintainers only)
rye publish
```

## Dependency Philosophy

ModelAudit uses optional dependencies to keep the base installation lightweight while supporting many ML frameworks:

- **Base install**: Only includes core dependencies (pickle, numpy, zip scanning)
- **Feature-specific installs**: Add only what you need (e.g., `[tensorflow]`, `[pytorch]`)
- **Graceful degradation**: Missing dependencies don't break the tool, just disable specific scanners
- **Clear guidance**: Error messages tell you exactly what to install

## Docker Support

Three Docker images available:

- `Dockerfile` - Lightweight base image
- `Dockerfile.tensorflow` - TensorFlow-specific image
- `Dockerfile.full` - All ML frameworks included

```bash
# Build and run Docker image
docker build -t modelaudit .
docker run -v $(pwd):/data modelaudit /data/model.pkl
```

## Commit Conventions

- **NEVER commit directly to the main branch** - always create a feature branch
- Use Conventional Commit format for ALL commit messages (e.g., `feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`)
- Keep commit messages concise and descriptive
- Examples:
  - `feat: add support for TensorFlow SavedModel scanning`
  - `fix: handle corrupt pickle files gracefully`
  - `test: add unit tests for ONNX scanner`
  - `chore: update dependencies to latest versions`

## Pull Request Guidelines

- **IMPORTANT**: Never push directly to main branch - always create a feature branch first
- **Branch naming**: Use conventional commit format (e.g., `feat/scanner-improvements`, `fix/pickle-parsing`, `chore/update-deps`)
- Create PRs using the GitHub CLI: `gh pr create`
- Keep PR bodies short and focused
- **Always include minimal test instructions** in PR body:
  ```
  ## Test Instructions
  rye run pytest tests/test_affected_component.py
  rye run modelaudit test-file.pkl
  ```
- Reference related issues when applicable
- Ensure all CI checks pass before requesting review
- **PR titles must follow Conventional Commits format** (validated by CI)
