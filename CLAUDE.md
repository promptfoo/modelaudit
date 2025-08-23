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

# Large Model Support (8 GB+)
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
- Model metadata security issues (exposed secrets, suspicious URLs, dangerous code references)

## Exit Codes

- 0: No security issues found
- 1: Security issues detected
- 2: Scan errors occurred

## Input Sources

ModelAudit supports multiple input sources:

- Local files and directories
- HuggingFace models: `hf://username/model` or `https://huggingface.co/username/model`
- HuggingFace direct files: `https://huggingface.co/username/model/resolve/<revision>/<path>` or `https://hf.co/username/model/resolve/<revision>/<path>`
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

````bash
# Diagnose scanner compatibility
rye run modelaudit doctor --show-failed

# Build package
rye build

# Publishing (maintainers only)

## Clean Publishing Process

```bash
# 1. Build package (clean first)
rye build --clean

# 2. Verify only current version artifacts exist
ls -la dist/

# 3. Publish to PyPI
rye publish --yes
````

## Manual Publishing Steps

For interactive authentication (if --yes doesn't work):

```bash
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
- **Each feature branch should add exactly one entry to CHANGELOG.md** in the [Unreleased] section following Keep a Changelog format
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

## CI Optimization Guide

### Pre-Push Validation (Essential)

**The Golden Rule**: Validate locally before pushing to get instant feedback instead of waiting 3-5 minutes for CI.

```bash
# Fast-fail approach - exit on first error to save time
set -e

# 1. Format check (fail fast if not formatted)
rye run ruff format --check modelaudit/ tests/ || {
    echo "❌ Format check failed - running formatter..."
    rye run ruff format modelaudit/ tests/
}

# 2. Lint check (must be clean before proceeding)
rye run ruff check modelaudit/ tests/ || exit 1

# 3. Type checking
rye run mypy modelaudit/ || exit 1

# 4. Quick tests (target your changes)
# See "Smart Test Execution" section below

# 5. Documentation formatting (if changed)
npx prettier@latest --write "**/*.{md,yaml,yml,json}"
```

### Smart Test Execution

Target tests related to your changes for faster feedback:

```bash
# For scanner changes
rye run pytest tests/test_*scanner*.py -k "not slow" -v

# For filetype/core changes
rye run pytest tests/test_filetype.py tests/test_core*.py -v

# For utility changes
rye run pytest tests/test_utils/ -v

# For specific module (example: pickle_scanner.py changes)
rye run pytest tests/test_pickle_scanner.py -v

# Full fast test suite (when unsure)
rye run pytest -n auto -m "not slow and not integration and not performance" -v
```

### Branch Hygiene

Clean merges prevent CI conflicts:

```bash
# Before making changes - get latest main
git fetch origin main
git merge --no-edit origin/main

# After changes - validate before pushing
# Run manual validation commands from above
git push origin your-branch-name
```

### CI Status Monitoring

Efficient CI status checking:

```bash
# Check only failed/in-progress checks
gh pr view <PR_NUMBER> --json statusCheckRollup --jq '
  .statusCheckRollup[] |
  select(.status == "IN_PROGRESS" or .conclusion == "FAILURE") |
  {name: .name, status: .status, conclusion: .conclusion}
'

# Monitor specific check
gh pr view <PR_NUMBER> --json statusCheckRollup --jq '
  .statusCheckRollup[] |
  select(.name == "Lint and Format") |
  {name: .name, conclusion: .conclusion}
'

# Quick overall status
gh pr view <PR_NUMBER> --json statusCheckRollup --jq '
  [.statusCheckRollup[] | select(.conclusion == "SUCCESS")] | length
' && echo "checks passing"
```

### Fast-Fail Patterns

Exit early on failures to save development time:

```bash
# Example validation script
#!/bin/bash
set -e  # Exit on any failure

echo "🔍 Checking format..."
rye run ruff format --check . || {
    echo "❌ Format issues found - run: rye run ruff format ."
    exit 1
}

echo "🔍 Checking lint..."
rye run ruff check . || {
    echo "❌ Lint issues found - run: rye run ruff check --fix ."
    exit 1
}

echo "🔍 Type checking..."
rye run mypy modelaudit/ || exit 1

echo "🔍 Running targeted tests..."
# Add your specific test commands here based on changes

echo "✅ All checks passed - safe to push!"
```

### Performance Tips

- **Local validation takes ~30 seconds vs 3-5 minutes in CI**
- **Target specific test files** instead of running full suite during development
- **Use `--maxfail=1`** with pytest to exit on first test failure
- **Check CI status efficiently** with jq filters to reduce noise
- **Keep branches clean** - merge main regularly to avoid conflicts
