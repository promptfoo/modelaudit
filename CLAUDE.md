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
rye run mypy modelaudit/                 # Type checking (mypy)
rye run ty check                         # Advanced type checking (ty - more strict than mypy)
npx prettier@latest --write "**/*.{md,yaml,yml,json}"  # Format markdown, YAML, JSON files

# CI Checks - ALWAYS run these before committing:
# 1. rye run ruff format modelaudit/ tests/
# 2. rye run ruff check modelaudit/ tests/  # IMPORTANT: Check without --fix first!
# 3. rye run ruff check --fix modelaudit/ tests/  # Then fix any issues
# 4. rye run mypy modelaudit/
# 5. rye run ty check                       # Advanced type checking (optional but recommended)
# 6. rye run pytest -n auto -m "not slow and not integration"  # Fast tests first
# 7. npx prettier@latest --write "**/*.{md,yaml,yml,json}"
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

### Security Check Guidelines

**CRITICAL: Only implement checks that represent real, documented security threats.**

**✅ ACCEPTABLE - Keep these checks:**

- **CVE-documented vulnerabilities**: Any check with a specific CVE number (e.g., CVE-2025-32434 for PyTorch pickle RCE, CVE-2025-54412/54413/54886 for skops RCE)
- **Real-world attacks**: Documented exploits that have actually compromised systems in the wild
- **Code execution vectors**: eval, exec, os.system, subprocess, \_\_import\_\_, compile
- **Path traversal**: ../, absolute paths to sensitive files (/etc/passwd, /proc/)
- **Compression bombs**: Documented thresholds (compression ratio >100x is a real zip bomb)
- **Dangerous opcodes**: Pickle REDUCE, INST, OBJ, NEWOBJ, STACK_GLOBAL that enable arbitrary code execution
- **Exposed secrets**: API keys, passwords, tokens in model metadata

**❌ UNACCEPTABLE - Remove these checks:**

- **Arbitrary thresholds**: "More than N items could be a DoS" without CVE backing
- **Format validation**: Checking alignment, field counts, block sizes, version numbers
- **"Seems suspicious" heuristics**: Large dimensions, deep nesting, long strings without exploit evidence
- **Theoretical DoS**: "This could potentially be slow" without documented attacks
- **Defensive programming**: "Better safe than sorry" checks that generate false positives

**ℹ️ UNCERTAIN - Downgrade to INFO severity:**

- Large counts/sizes that might indicate issues but have no CVE (e.g., >100k files in archive)
- Unusual patterns that could be legitimate (e.g., unexpected metadata keys)
- Informational warnings that don't indicate actual compromise

**The Standard**: If challenged with "Show me the CVE or documented attack", you must be able to provide evidence. No evidence = remove the check.

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
- JFrog Artifactory URLs (files and folders): `https://company.jfrog.io/artifactory/repo/model.pt` or `https://company.jfrog.io/artifactory/repo/models/`
- DVC pointer files (`.dvc`)

## Model Whitelist System

ModelAudit includes a whitelist system that reduces false positives for trusted models:

- **7,440+ whitelisted models** from popular downloads and trusted organizations
- Security findings for whitelisted models are automatically downgraded to INFO severity
- Whitelisting is **enabled by default** but can be disabled via config: `{"use_hf_whitelist": False}`

### Updating the Whitelist

The whitelist should be updated periodically to include new popular models and organization releases:

```bash
# Update popular models whitelist (top downloads)
python scripts/fetch_hf_top_models.py --count 2000

# Update organization models whitelist (trusted orgs)
python scripts/fetch_hf_org_models.py

# Both commands regenerate the whitelist modules in modelaudit/whitelists/
# Commit the updated files after running
```

**When to update:**

- Monthly or quarterly for popular models (trends change)
- When new trusted organizations emerge
- Before major releases to ensure up-to-date coverage

**Whitelist sources:**

1. `huggingface_popular.py` - Top downloaded models from HuggingFace
2. `huggingface_organizations.py` - Models from 18 trusted organizations (Meta, Google, Microsoft, NVIDIA, etc.)

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

## Advanced Type Checking with ty

ty is a modern Python type checker that provides more advanced analysis than mypy. It's integrated as an optional quality assurance tool.

```bash
# Basic type checking
rye run ty check                         # Check all configured files

# Specific file or directory checking
rye run ty check modelaudit/cli.py       # Check specific file
rye run ty check modelaudit/scanners/    # Check specific directory

# Configuration and debugging
rye run ty check --verbose               # Verbose output for debugging
rye run ty check --output-format full    # Full diagnostic format (default is concise)
rye run ty check --help                  # See all available options

# Integration with development workflow
rye run ty check --error-on-warning      # Treat warnings as errors (stricter CI)
```

### ty vs mypy

- **mypy**: Established type checker, good for existing codebases, configurable strictness
- **ty**: Modern, fast type checker with advanced analysis, catches subtle bugs mypy might miss
- **Usage**: Run both - mypy for baseline type safety, ty for advanced quality assurance
- **CI Integration**: ty is optional in CI (step 5) but recommended for high-quality code

### ty Configuration

Configuration is in `[tool.ty]` section of `pyproject.toml`:

- Includes both `modelaudit/` and `tests/` directories
- Excludes test assets and generated files
- Conservative rule configuration to avoid overwhelming output
- Test files have more permissive rules than source code

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

# Type checking validation (after code changes)
rye run mypy modelaudit/                 # Essential type checking
rye run ty check modelaudit/scanners/    # Advanced type checking for specific area
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
